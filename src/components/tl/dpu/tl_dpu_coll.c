/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "tl_dpu.h"
#include "tl_dpu_coll.h"

#include "core/ucc_mc.h"
#include "core/ucc_ee.h"
#include "utils/ucc_math.h"
#include "utils/ucc_coll_utils.h"
#include "../../../core/ucc_team.h"

ucc_status_t ucc_tl_dpu_req_test(ucs_status_ptr_t *req_p, ucp_worker_h worker)
{
    ucs_status_t status;
    ucs_status_ptr_t request = *req_p;
    if (request == NULL) {
        status = UCS_OK;
    }
    else if (UCS_PTR_IS_ERR(request)) {
        fprintf (stderr, "unable to complete UCX request\n");
        status = UCS_PTR_STATUS(request);
    }
    else {
        status = ucp_request_check_status(request);
        if (UCS_OK == status) {
            ucp_request_free(request);
            *req_p = NULL;
        }
    }
    return ucs_status_to_ucc_status(status);
}

ucc_status_t ucc_tl_dpu_req_check(ucc_tl_dpu_team_t *team,
                                      ucs_status_ptr_t req) {
    if (UCS_PTR_IS_ERR(req)) {
        tl_error(team->super.super.context->lib,
                 "failed to send/recv msg");
        return UCC_ERR_NO_MESSAGE;
    }
    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_req_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t request)
{
    ucs_status_t status;

    /* immediate completion */
    if (request == NULL) {
        return UCC_OK;
    }
    else if (UCS_PTR_IS_ERR(request)) {
        status = ucp_request_check_status(request);
        fprintf (stderr, "unable to complete UCX request (%s)\n", ucs_status_string(status));
        return UCS_PTR_STATUS(request);
    }
    else {
        do {
            ucp_worker_progress(ucp_worker);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(request);
    }

    return UCC_OK;
}

ucs_status_t ucc_tl_dpu_register_buf(
    ucp_context_h ucp_ctx,
    void *base, size_t size,
    ucc_tl_dpu_rkey_t *rkey)
{
    ucp_mem_attr_t mem_attr;
    ucs_status_t status;
    ucp_mem_map_params_t mem_params = {
        .address = base,
        .length = size,
        .field_mask = UCP_MEM_MAP_PARAM_FIELD_FLAGS  |
                      UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                      UCP_MEM_MAP_PARAM_FIELD_ADDRESS,
    };

    status = ucp_mem_map(ucp_ctx, &mem_params, &rkey->memh);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_mem_map (%s)\n", ucs_status_string(status));
        goto out;
    }

    mem_attr.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS |
                          UCP_MEM_ATTR_FIELD_LENGTH;

    status = ucp_mem_query(rkey->memh, &mem_attr);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_mem_query (%s)\n", ucs_status_string(status));
        goto err_map;
    }
    assert(mem_attr.length >= size);
    assert(mem_attr.address <= base);

    status = ucp_rkey_pack(ucp_ctx, rkey->memh, &rkey->rkey_buf, &rkey->rkey_buf_size);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_rkey_pack (%s)\n", ucs_status_string(status));
        goto err_map;
    }
    assert(rkey->rkey_buf_size < MAX_RKEY_LEN);

    goto out;
err_map:
    ucp_mem_unmap(ucp_ctx, rkey->memh);
out:
    return status;
}

ucc_status_t ucc_tl_dpu_deregister_buf(
    ucp_context_h ucp_ctx, ucc_tl_dpu_rkey_t *rkey)
{
    ucs_status_t status = UCS_OK;
    status = ucp_mem_unmap(ucp_ctx, rkey->memh);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_mem_unmap (%s)\n", ucs_status_string(status));
        goto out;
    }
    ucp_rkey_buffer_release(rkey->rkey_buf);
out:
    return status;
}

static ucc_status_t ucc_tl_dpu_init_rkeys(ucc_tl_dpu_task_t *task)
{
    ucc_status_t status = UCC_OK;
    ucc_tl_dpu_context_t *ctx = UCC_TL_DPU_TEAM_CTX(task->team);
    int rail;
    void *src_buf = task->args.src.info.buffer;
    void *dst_buf = task->args.dst.info.buffer;
    size_t src_len = task->args.src.info.count * ucc_dt_size(task->args.src.info.datatype);
    size_t dst_len = task->args.dst.info.count * ucc_dt_size(task->args.dst.info.datatype);

    for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
        status |= ucc_tl_dpu_register_buf(ctx->dpu_ctx_list[rail].ucp_context,
                src_buf, src_len, &task->dpu_task_list[rail].src_rkey);
        status |= ucc_tl_dpu_register_buf(ctx->dpu_ctx_list[rail].ucp_context,
                dst_buf, dst_len, &task->dpu_task_list[rail].dst_rkey);
    }
    return status;
}

static void ucc_tl_dpu_finalize_rkeys(ucc_tl_dpu_task_t *task)
{
    int rail;
    ucc_tl_dpu_context_t *ctx = UCC_TL_DPU_TEAM_CTX(task->team);

    for (rail = 0; rail < ctx->dpu_per_node_cnt; rail++) { 
        ucc_tl_dpu_deregister_buf(ctx->dpu_ctx_list[rail].ucp_context,
                &task->dpu_task_list[rail].src_rkey);
        ucc_tl_dpu_deregister_buf(ctx->dpu_ctx_list[rail].ucp_context,
                &task->dpu_task_list[rail].dst_rkey);
        task->dpu_task_list[rail].status = UCC_TL_DPU_TASK_STATUS_FINALIZED; 
    }
}

static void ucc_tl_dpu_init_put(ucc_tl_dpu_context_t *ctx,
    ucc_tl_dpu_task_t *task, ucc_tl_dpu_team_t *team, int rail)
{
    ucc_tl_dpu_put_sync_t *put_sync = &task->dpu_task_list[rail].put_sync;
    ucc_tl_dpu_sub_task_t *dpu_task = &task->dpu_task_list[rail];

    memcpy(put_sync->rkeys.src_rkey, dpu_task->src_rkey.rkey_buf,
            dpu_task->src_rkey.rkey_buf_size);
    memcpy(put_sync->rkeys.dst_rkey, dpu_task->dst_rkey.rkey_buf,
            dpu_task->dst_rkey.rkey_buf_size);

    put_sync->rkeys.src_rkey_len = dpu_task->src_rkey.rkey_buf_size;
    put_sync->rkeys.dst_rkey_len = dpu_task->dst_rkey.rkey_buf_size;
    put_sync->rkeys.src_buf = task->args.src.info.buffer;
    put_sync->rkeys.dst_buf = task->args.dst.info.buffer;
}

static ucc_status_t ucc_tl_dpu_issue_put( ucc_tl_dpu_task_t *task,
    ucc_tl_dpu_context_t *ctx, ucc_tl_dpu_team_t *team, int rail)
{
    ucc_tl_dpu_put_request_t *put_req = &task->dpu_task_list[rail].task_reqs.put_req;
    ucp_request_param_t req_param = {0};
    ucc_tl_dpu_sub_task_t *dpu_task = &task->dpu_task_list[rail];

    assert(task->dpu_task_list[rail].status != UCC_TL_DPU_TASK_STATUS_POSTED);
    task->dpu_task_list[rail].status = UCC_TL_DPU_TASK_STATUS_POSTED;
    ucc_tl_dpu_init_put(ctx, task, team, rail);
    assert(put_req->sync_req == NULL);

    ucp_worker_fence(ctx->dpu_ctx_list[rail].ucp_worker);
    put_req->sync_req =
        ucp_put_nbx(ctx->dpu_ctx_list[rail].ucp_ep, &dpu_task->put_sync,
                sizeof(dpu_task->put_sync), team->dpu_sync_list[rail].rem_ctrl_seg,
                team->dpu_sync_list[rail].rem_ctrl_seg_key, &req_param);
    if (ucc_tl_dpu_req_check(team, put_req->sync_req) != UCC_OK) {
        return UCC_ERR_NO_MESSAGE;
    }
    tl_info(UCC_TL_TEAM_LIB(task->team), "Sent task to DPU: %p, coll type %d id %d count %u",
            task, dpu_task->put_sync.coll_type, dpu_task->put_sync.coll_id,
            dpu_task->put_sync.count_total);
 
    ucc_tl_dpu_req_wait(ctx->dpu_ctx_list[rail].ucp_worker, put_req->sync_req);
    put_req->sync_req = NULL;
    // ucp_worker_flush(ctx->dpu_ctx_list[rail].ucp_worker);
    return UCC_OK;
}

static ucc_status_t ucc_tl_dpu_check_progress(
    ucc_tl_dpu_task_t *task, ucc_tl_dpu_context_t *ctx)
{
    int i;
    ucc_tl_dpu_team_t *team = task->team;
    ucc_status_t status;
    int rail = 0, rail_progressed_cnt = 0, rail_put_cnt = 0;

    // tl_info(UCC_TL_TEAM_LIB(task->team), "task status %d coll id %d", task->status, task->put_sync.coll_id);
    if (task->status == UCC_TL_DPU_TASK_STATUS_INIT) {
        for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
            if (task->dpu_task_list[rail].status ==
                    UCC_TL_DPU_TASK_STATUS_INIT &&
                    task->dpu_task_list[rail].put_sync.coll_id ==
                    team->dpu_sync_list[rail].coll_id_completed + 1) {
                tl_info(UCC_TL_TEAM_LIB(task->team), 
                        "Put to DPU rail: %d coll task: %p, coll id %d", 
                        rail, task, task->dpu_task_list[rail].put_sync.coll_id);
                status = ucc_tl_dpu_issue_put(task, ctx, team, rail);
                if (UCC_OK != status) {
                    return UCC_INPROGRESS;
                }
            }
        }
        for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
            if (task->dpu_task_list[rail].status == UCC_TL_DPU_TASK_STATUS_POSTED) {
                rail_put_cnt++;
            }
        }
        if (rail_put_cnt == task->dpu_per_node_cnt) {
            task->status = UCC_TL_DPU_TASK_STATUS_POSTED;
        }
    }

    for (i = 0; i < UCC_TL_DPU_TC_POLL; i++) {
        for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
            if (ucp_worker_progress(ctx->dpu_ctx_list[rail].ucp_worker)) {
                break;
            }
        }
    }

    if (task->status == UCC_TL_DPU_TASK_STATUS_POSTED) {
        for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
            if (ctx->dpu_ctx_list[rail].get_sync.coll_id <
                    task->dpu_task_list[rail].put_sync.coll_id ||
                    ctx->dpu_ctx_list[rail].get_sync.count_serviced <
                    task->dpu_task_list[rail].put_sync.count_total) {
                return UCC_INPROGRESS;
            }
            else if (task->dpu_task_list[rail].status != UCC_TL_DPU_TASK_STATUS_DONE) {
                task->dpu_task_list[rail].get_sync.coll_id           =
                    ctx->dpu_ctx_list[rail].get_sync.coll_id;
                ctx->dpu_ctx_list[rail].get_sync.count_serviced     =
                    ctx->dpu_ctx_list[rail].get_sync.count_serviced;
                ctx->dpu_ctx_list[rail].get_sync.coll_id            = 0;
                ctx->dpu_ctx_list[rail].get_sync.count_serviced     = 0;

                ctx->dpu_ctx_list[rail].coll_id_completed++;
                team->dpu_sync_list[rail].coll_id_completed =
                    ctx->dpu_ctx_list[rail].coll_id_completed;
                assert(team->dpu_sync_list[rail].coll_id_completed ==
                        task->dpu_task_list[rail].get_sync.coll_id);

                task->dpu_task_list[rail].status = UCC_TL_DPU_TASK_STATUS_DONE;
            }    
        }

        for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
            if (task->dpu_task_list[rail].status == UCC_TL_DPU_TASK_STATUS_DONE) {
                rail_progressed_cnt++;
            }
        }
        if (rail_progressed_cnt == task->dpu_per_node_cnt) {
            task->status = UCC_TL_DPU_TASK_STATUS_DONE;
            return UCC_OK;
        }
    }

    return UCC_INPROGRESS;
}

ucc_status_t ucc_tl_dpu_allreduce_progress(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t       *task =
        ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_context_t *ctx     = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_status_t            status;

    status = ucc_tl_dpu_check_progress(task, ctx);
    coll_task->super.status = status;

    return status;
}

ucc_status_t ucc_tl_dpu_allreduce_start(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t    *task        = ucs_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_team_t    *team        = task->team;
    ucc_status_t         status;

    tl_info(UCC_TL_TEAM_LIB(task->team), "Allreduce start task %p coll id %d", task, task->put_sync.coll_id);

    coll_task->super.status = UCC_INPROGRESS;
    status = ucc_tl_dpu_allreduce_progress(coll_task);
    if (UCC_INPROGRESS == status) {
        ucc_progress_enqueue(UCC_TL_DPU_TEAM_CORE_CTX(team)->pq, coll_task);
        return UCC_OK;
    }

    return ucc_task_complete(coll_task);
}

ucc_status_t ucc_tl_dpu_allreduce_init(ucc_tl_dpu_task_t *task)
{
    ucc_coll_args_t      *coll_args = &task->args;
    ucc_tl_dpu_team_t    *team      = task->team;
    ucc_base_team_t      *base_team = &team->super.super;
    ucc_tl_dpu_context_t *ctx       = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_tl_dpu_put_sync_t *task_put_sync = NULL;
    int rail, rail_put_cnt = 0;

    if (task->args.mask & UCC_COLL_ARGS_FIELD_USERDEFINED_REDUCTIONS) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "userdefined reductions are not supported yet");
        return UCC_ERR_NOT_SUPPORTED;
    }
    if (!UCC_IS_INPLACE(task->args) && (task->args.src.info.mem_type !=
                                        task->args.dst.info.mem_type)) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "assymetric src/dst memory types are not supported yet");
        return UCC_ERR_NOT_SUPPORTED;
    }

    if (UCC_IS_INPLACE(task->args)) {
        task->args.src.info.buffer   = task->args.dst.info.buffer;
        task->args.dst.info.count    = task->args.src.info.count;
        task->args.dst.info.datatype = task->args.src.info.datatype;
        task->args.dst.info.mem_type = task->args.src.info.mem_type;
    }

    task->super.post     = ucc_tl_dpu_allreduce_start;
    task->super.progress = ucc_tl_dpu_allreduce_progress;

    ucc_tl_dpu_init_rkeys(task);

    assert(task->status == UCC_TL_DPU_TASK_STATUS_INIT);

    /* Set sync information for DPU */
    for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {

        task_put_sync = &task->dpu_task_list[rail].put_sync;

        task_put_sync->coll_id           =
        team->dpu_sync_list[rail].coll_id_issued;
        task_put_sync->dtype             = coll_args->src.info.datatype;
        task_put_sync->count_total       = coll_args->src.info.count;
        task_put_sync->op                = coll_args->reduce.predefined_op;
        task_put_sync->coll_type         = coll_args->coll_type;
        task_put_sync->team_id           = base_team->params.id;
        task_put_sync->create_new_team   = 0;

        assert(task->dpu_task_list[rail].status ==
                UCC_TL_DPU_TASK_STATUS_INIT);
        if (task_put_sync->coll_id == ctx->dpu_ctx_list[rail].coll_id_completed
                + 1) {
            tl_info(UCC_TL_TEAM_LIB(team), 
                    "Put to DPU rail: %d coll task: %p, coll id %d",
                    rail, task, task_put_sync->coll_id);
            ucc_tl_dpu_issue_put(task, ctx, team, rail);
        }
    }

    for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {
        if (task->dpu_task_list[rail].status == UCC_TL_DPU_TASK_STATUS_POSTED) {
            rail_put_cnt++;
        }
    }
    if (rail_put_cnt == task->dpu_per_node_cnt) {
        task->status = UCC_TL_DPU_TASK_STATUS_POSTED;
    }

    return UCC_OK;
}


ucc_status_t ucc_tl_dpu_alltoall_progress(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t       *task =
        ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_context_t *ctx     = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_status_t            status;

    status = ucc_tl_dpu_check_progress(task, ctx);
    coll_task->super.status = status;

    return status;
}

ucc_status_t ucc_tl_dpu_alltoall_start(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t    *task        = ucs_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_team_t    *team        = task->team;
    ucc_status_t         status;
 
    tl_info(UCC_TL_TEAM_LIB(task->team), "Alltoall start task %p coll id %d", 
            task, task->dpu_task_list[0].put_sync.coll_id);

    status = ucc_tl_dpu_alltoall_progress(coll_task);
    if (UCC_INPROGRESS == status) {
        ucc_progress_enqueue(UCC_TL_DPU_TEAM_CORE_CTX(team)->pq, coll_task);
        return UCC_OK;
    }

    return ucc_task_complete(coll_task);
}

ucc_status_t ucc_tl_dpu_alltoall_init(ucc_tl_dpu_task_t *task)
{
    ucc_coll_args_t     *coll_args = &task->args;
    ucc_tl_dpu_team_t   *team      = task->team;
    ucc_base_team_t     *base_team = &team->super.super;
    ucc_tl_dpu_put_sync_t *task_put_sync = NULL;
    int rail;

    if (!UCC_IS_INPLACE(task->args) && (task->args.src.info.mem_type !=
                                        task->args.dst.info.mem_type)) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "assymetric src/dst memory types are not supported yet");
        return UCC_ERR_NOT_SUPPORTED;
    }

    if (UCC_IS_INPLACE(task->args)) {
        task->args.src.info.buffer = task->args.dst.info.buffer;
    }

    task->super.post     = ucc_tl_dpu_alltoall_start;
    task->super.progress = ucc_tl_dpu_alltoall_progress;

    ucc_tl_dpu_init_rkeys(task);

    /* Set sync information for DPU */
    for (rail = 0; rail < task->dpu_per_node_cnt; rail++) {

        task_put_sync = &task->dpu_task_list[rail].put_sync;

        task_put_sync->coll_id           = team->dpu_sync_list[rail].coll_id_issued;
        task_put_sync->dtype             = coll_args->src.info.datatype;
        task_put_sync->count_total       = coll_args->src.info.count;
        task_put_sync->coll_type         = coll_args->coll_type;
        task_put_sync->team_id           = base_team->params.id;
        task_put_sync->create_new_team   = 0;
    }


    return UCC_OK;
}

static ucc_status_t ucc_tl_dpu_coll_finalize(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t *task = ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    tl_info(UCC_TL_TEAM_LIB(task->team),
            "finalizing task %p, task status %d, coll status %d, coll id %u",
            task, task->status, coll_task->super.status,
            task->dpu_task_list[0].get_sync.coll_id);

    assert(coll_task->super.status == UCC_OK);
    if(task->status == UCC_TL_DPU_TASK_STATUS_FINALIZED) {
        tl_warn(UCC_TL_TEAM_LIB(task->team),
                 "task %p already finalized, status %d, coll id %u",
                 task, task->status, task->dpu_task_list[0].get_sync.coll_id);
        return UCC_OK;
    }

    //assert(task->status == UCC_TL_DPU_TASK_STATUS_DONE);
    //assert(task->get_sync.coll_id == task->put_sync.coll_id);
    //assert(task->get_sync.count_serviced == task->put_sync.count_total);
    ucc_tl_dpu_finalize_rkeys(task);
    task->status = UCC_TL_DPU_TASK_STATUS_FINALIZED;
    ucc_mpool_put(task);
    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_coll_init(ucc_base_coll_args_t      *coll_args,
                                         ucc_base_team_t    *team,
                                         ucc_coll_task_t    **task_h)
{
    ucc_tl_dpu_team_t    *tl_team = ucc_derived_of(team, ucc_tl_dpu_team_t);
    ucc_tl_dpu_context_t *ctx     = UCC_TL_DPU_TEAM_CTX(tl_team);
    ucc_tl_dpu_task_t    *task;
    ucc_status_t          status;
    int rail;

    task = ucc_mpool_get(&ctx->req_mp);

    ucc_coll_task_init(&task->super, coll_args, team);
    tl_info(team->context->lib, "task %p initialized", task);

    memcpy(&task->args, &coll_args->args, sizeof(ucc_coll_args_t));

    /* Misc init stuff */
    task->team                       = tl_team;
    task->super.finalize             = ucc_tl_dpu_coll_finalize;
    task->super.triggered_post       = NULL;
    task->status                     = UCC_TL_DPU_TASK_STATUS_INIT;
    task->dpu_per_node_cnt           = ctx->dpu_per_node_cnt;

    for (rail = 0; rail < ctx->dpu_per_node_cnt; rail++) { 
        task->dpu_task_list[rail].status = UCC_TL_DPU_TASK_STATUS_INIT;
        ctx->dpu_ctx_list[rail].coll_id_issued++;
        tl_team->dpu_sync_list[rail].coll_id_issued =
            ctx->dpu_ctx_list[rail].coll_id_issued;
    }

    switch (coll_args->args.coll_type) {
    case UCC_COLL_TYPE_ALLREDUCE:
        status = ucc_tl_dpu_allreduce_init(task);
        break;
    case UCC_COLL_TYPE_ALLTOALL:
        status = ucc_tl_dpu_alltoall_init(task);
        break;
    default:
        status = UCC_ERR_NOT_SUPPORTED;
    }
    if (status != UCC_OK) {
        ucc_mpool_put(task);
        return status;
    }

    tl_info(team->context->lib, "init coll req %p coll id %d", 
            task, tl_team->dpu_sync_list[0].coll_id_issued);
    *task_h = &task->super;

    return status;
}

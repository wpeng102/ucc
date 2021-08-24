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

void ucc_tl_dpu_send_handler_nbx(void *request, ucs_status_t status,
                                 void *user_data)
{
    ucc_tl_dpu_request_t *req = (ucc_tl_dpu_request_t *)request;
    req->status = UCC_TL_DPU_UCP_REQUEST_DONE;
}

void ucc_tl_dpu_recv_handler_nbx(void *request, ucs_status_t status,
                      const ucp_tag_recv_info_t *tag_info,
                      void *user_data)
{
  ucc_tl_dpu_request_t *req = (ucc_tl_dpu_request_t *)request;
  req->status = UCC_TL_DPU_UCP_REQUEST_DONE;
}

static ucc_tl_dpu_task_t * ucc_tl_dpu_alloc_task(void)
{
    ucc_tl_dpu_task_t *task =
        (ucc_tl_dpu_task_t *) ucc_calloc(1, sizeof(ucc_tl_dpu_task_t),
                                         "Allocate task");
    return task;
}

static ucc_status_t ucc_tl_dpu_free_task(ucc_tl_dpu_task_t *task)
{
    ucc_free(task);
    return UCC_OK;
}

void ucc_tl_dpu_req_init(void* request)
{
    ucc_tl_dpu_request_t *req = (ucc_tl_dpu_request_t *)request;
    req->status = UCC_TL_DPU_UCP_REQUEST_ACTIVE;
}

void ucc_tl_dpu_req_cleanup(void* request){ 
    return;
}

ucc_status_t ucc_tl_dpu_req_test(ucc_tl_dpu_request_t **req,
                                 ucp_worker_h worker) {
    if (*req == NULL) {
        return UCC_OK;
    }

    if ((*req)->status == UCC_TL_DPU_UCP_REQUEST_DONE) {
        (*req)->status = UCC_TL_DPU_UCP_REQUEST_ACTIVE;
        ucp_request_free(*req);
        (*req) = NULL;
        return UCC_OK;
    }
    ucp_worker_progress(worker);
    return UCC_INPROGRESS;
}

inline
ucc_status_t ucc_tl_dpu_req_check(ucc_tl_dpu_team_t *team,
                                      ucc_tl_dpu_request_t *req) {
    if (UCS_PTR_IS_ERR(req)) {
        tl_error(team->super.super.context->lib,
                 "failed to send/recv msg");
        return UCC_ERR_NO_MESSAGE;
    }
    return UCC_OK;
}

static ucs_status_t ucc_tl_dpu_register_buf(
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

    fprintf(stderr, "base: %p size: %lu rkey buf: %p len: %lu\n", base, size, rkey->rkey_buf, rkey->rkey_buf_size);
    goto out;
err_map:
    ucp_mem_unmap(ucp_ctx, rkey->memh);
out:
    return status;
}

static void ucc_tl_dpu_deregister_buf(
    ucp_context_h ucp_ctx, ucc_tl_dpu_rkey_t *rkey)
{
    ucp_mem_unmap(ucp_ctx, rkey->memh);
    ucp_rkey_buffer_release(rkey->rkey_buf);
}

static ucc_status_t ucc_tl_dpu_init_rkeys(ucc_tl_dpu_task_t *task)
{
    ucc_status_t status = UCC_OK;
    ucc_tl_dpu_context_t *ctx = UCC_TL_DPU_TEAM_CTX(task->team);
    void *src_buf = task->args.src.info.buffer;
    void *dst_buf = task->args.dst.info.buffer;
    size_t src_len = task->args.src.info.count * ucc_dt_size(task->args.src.info.datatype);
    size_t dst_len = task->args.src.info.count * ucc_dt_size(task->args.src.info.datatype);

    fprintf(stderr, "src count: %lu, len: %zu, dst count %lu, len %zu\n", task->args.src.info.count, src_len, task->args.dst.info.count, dst_len);
    status |= ucc_tl_dpu_register_buf(ctx->ucp_context, src_buf, src_len, &task->src_rkey);
    status |= ucc_tl_dpu_register_buf(ctx->ucp_context, dst_buf, dst_len, &task->dst_rkey);

    return status;
}

static void ucc_tl_dpu_finalize_rkeys(ucc_tl_dpu_task_t *task)
{
    ucc_tl_dpu_context_t *ctx = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_tl_dpu_deregister_buf(ctx->ucp_context, &task->src_rkey);
    ucc_tl_dpu_deregister_buf(ctx->ucp_context, &task->dst_rkey);
}

static void ucc_tl_dpu_init_put(ucc_tl_dpu_context_t *ctx,
    ucc_tl_dpu_task_t *task, ucc_tl_dpu_team_t *team)
{
    ucc_tl_dpu_put_sync_t *put_sync = &task->put_sync;
    memcpy(put_sync->rkeys.src_rkey, task->src_rkey.rkey_buf, task->src_rkey.rkey_buf_size);
    memcpy(put_sync->rkeys.dst_rkey, task->dst_rkey.rkey_buf, task->dst_rkey.rkey_buf_size);
    put_sync->rkeys.src_rkey_len = task->src_rkey.rkey_buf_size;
    put_sync->rkeys.dst_rkey_len = task->dst_rkey.rkey_buf_size;
    put_sync->rkeys.src_buf = task->args.src.info.buffer;
    put_sync->rkeys.dst_buf = task->args.dst.info.buffer;
}

static ucc_status_t ucc_tl_dpu_issue_put( ucc_tl_dpu_task_t *task,
    ucc_tl_dpu_context_t *ctx, ucc_tl_dpu_team_t *team, void *sbuf,
    ucp_request_param_t *req_param)
{
    ucc_tl_dpu_put_request_t *put_req = &task->task_reqs.put_req;

    ucp_worker_fence(ctx->ucp_worker);
    ucc_tl_dpu_init_put(ctx, task, team);
    //memcpy(&put_req->sync_data, &task->put_sync, sizeof(task->put_sync));

    put_req->sync_req =
        ucp_put_nbx(ctx->ucp_ep, &task->put_sync, sizeof(task->put_sync),
                    team->rem_ctrl_seg, team->rem_ctrl_seg_key,
                    req_param);
    if (ucc_tl_dpu_req_check(team, put_req->sync_req) != UCC_OK) {
        return UCC_ERR_NO_MESSAGE;
    }
 
    ucp_worker_fence(ctx->ucp_worker);
    return UCC_OK;
}

static ucc_status_t ucc_tl_dpu_check_progress(
    ucc_tl_dpu_task_t *task, ucc_tl_dpu_context_t *ctx)
{
    int i = 0, j = 0, coll_poll = UCC_TL_DPU_COLL_POLL;
    ucc_tl_dpu_team_t *team = task->team;
    ucc_tl_dpu_put_request_t *put_req;
    ucc_status_t status;

    ucp_worker_progress(ctx->ucp_worker);

    __sync_synchronize();
    if (team->get_sync.coll_id < task->put_sync.coll_id ||
        team->get_sync.count_serviced < task->put_sync.count_total) {
        return UCC_INPROGRESS;
    } else {
        return UCC_OK;
    }
}

ucc_status_t ucc_tl_dpu_allreduce_progress(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t       *task =
        ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_context_t *ctx     = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_status_t            status;

    status = ucc_tl_dpu_check_progress(task, ctx);
    task->super.super.status = status;

    return status;
}

ucc_status_t ucc_tl_dpu_allreduce_start(ucc_coll_task_t *coll_task)
{
    // fprintf (stdout, "sleeping %d\n", getpid());
    // // sleep(20);

    ucc_tl_dpu_task_t    *task        = ucs_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_team_t    *team        = task->team;
    ucc_tl_dpu_context_t *ctx         = UCC_TL_DPU_TEAM_CTX(team);
    void                 *sbuf        = task->args.src.info.buffer;
    void                 *rbuf        = task->args.dst.info.buffer;
    size_t               count_total  = task->args.src.info.count;
    ucc_datatype_t       dt           = task->args.src.info.datatype;
    size_t               dt_size      = ucc_dt_size(dt);
    ucp_request_param_t  *req_param;
    ucc_status_t         status;
 
    tl_info(team->super.super.context->lib, "Allreduce post");

    if (UCC_IS_INPLACE(task->args)) {
        sbuf = task->args.src.info.buffer = rbuf;
    }

    req_param = &task->task_reqs.req_param;
    memset(req_param, 0, sizeof(ucp_request_param_t));
    req_param->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                              UCP_OP_ATTR_FIELD_DATATYPE;
    req_param->datatype     = ucp_dt_make_contig(1);
    req_param->cb.send      = ucc_tl_dpu_send_handler_nbx;
    req_param->cb.recv      = ucc_tl_dpu_recv_handler_nbx;

    /* XXX set memory
    req_param.mask          = 0;
    req_param.mem_type      = task->args.src.info.mem_type;
    req_param.memory_type   = ucc_memtype_to_ucs[mtype];
    */

   /* First put */
    status = ucc_tl_dpu_issue_put(task, ctx, team, sbuf, req_param);
    if (UCC_OK != status) {
        goto put_err;
    }

    status = ucc_tl_dpu_check_progress(task, ctx);
    task->super.super.status = status;

    if (UCC_INPROGRESS == status) {
        status = ucc_tl_dpu_allreduce_progress(&task->super);
        if (UCC_INPROGRESS == status) {
            ucc_progress_enqueue(UCC_TL_DPU_TEAM_CORE_CTX(team)->pq, &task->super);
            return UCC_OK;
        }
    }

    return UCC_OK;
put_err:
    return UCC_ERR_NO_MESSAGE;
}

ucc_status_t ucc_tl_dpu_allreduce_init(ucc_tl_dpu_task_t *task)
{
    ucc_coll_args_t      *coll_args = &task->args;
    ucc_tl_dpu_team_t    *team      = task->team;
    ucc_tl_dpu_context_t *ctx       = UCC_TL_DPU_TEAM_CTX(team);

    if (task->args.mask & UCC_COLL_ARGS_FIELD_USERDEFINED_REDUCTIONS) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "userdefined reductions are not supported yet");
        return UCC_ERR_NOT_SUPPORTED;
    }
    if (!UCC_IS_INPLACE(task->args) && (task->args.src.info.mem_type !=
                                        task->args.dst.info.mem_type)) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "assymetric src/dst memory types are not supported yetpp");
        return UCC_ERR_NOT_SUPPORTED;
    }

    /* Set sync information for DPU */
    task->put_sync.coll_id           = team->coll_id;
    task->put_sync.dtype             = coll_args->src.info.datatype;
    task->put_sync.count_total       = coll_args->src.info.count;
    task->put_sync.op                = coll_args->reduce.predefined_op;
    task->put_sync.coll_type         = coll_args->coll_type;
    task->get_sync.coll_id           = 0;
    task->get_sync.count_serviced    = 0;

    task->super.post     = ucc_tl_dpu_allreduce_start;
    task->super.progress = ucc_tl_dpu_allreduce_progress;

    return UCC_OK;
}


ucc_status_t ucc_tl_dpu_alltoall_progress(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t       *task =
        ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_context_t *ctx     = UCC_TL_DPU_TEAM_CTX(task->team);
    ucc_status_t            status;

    status = ucc_tl_dpu_check_progress(task, ctx);
    task->super.super.status = status;

    return status;
}

ucc_status_t ucc_tl_dpu_alltoall_start(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t    *task        = ucs_derived_of(coll_task, ucc_tl_dpu_task_t);
    ucc_tl_dpu_team_t    *team        = task->team;
    ucc_tl_dpu_context_t *ctx         = UCC_TL_DPU_TEAM_CTX(team);
    void                 *sbuf        = task->args.src.info.buffer;
    void                 *rbuf        = task->args.dst.info.buffer;
    size_t               count_total  = task->args.src.info.count;
    //ucc_datatype_t       dt           = task->args.src.info.datatype;
    //size_t               dt_size      = ucc_dt_size(dt);
    ucp_request_param_t  *req_param;
    ucc_status_t         status;
 
    tl_info(team->super.super.context->lib, "Alltoall post");

    if (UCC_IS_INPLACE(task->args)) {
        sbuf = task->args.src.info.buffer = rbuf;
    }
    
    req_param = &task->task_reqs.req_param;
    req_param->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                              UCP_OP_ATTR_FIELD_DATATYPE;
    req_param->datatype     = ucp_dt_make_contig(1);
    req_param->cb.send      = ucc_tl_dpu_send_handler_nbx;
    req_param->cb.recv      = ucc_tl_dpu_recv_handler_nbx;

    status = ucc_tl_dpu_issue_put(task, ctx, team, sbuf, req_param);
    if (UCC_OK != status) {
        goto put_err;
    }

    status = ucc_tl_dpu_check_progress(task, ctx);
    task->super.super.status = status;

    if (UCC_INPROGRESS == status) {
        status = ucc_tl_dpu_alltoall_progress(&task->super);
        if (UCC_INPROGRESS == status) {
            ucc_progress_enqueue(UCC_TL_DPU_TEAM_CORE_CTX(team)->pq, &task->super);
            return UCC_OK;
        }
    }

    return UCC_OK;
put_err:
    return UCC_ERR_NO_MESSAGE;
}

ucc_status_t ucc_tl_dpu_alltoall_init(ucc_tl_dpu_task_t *task)
{
    ucc_coll_args_t     *coll_args = &task->args;
    ucc_tl_dpu_team_t   *team      = task->team;

    if (!UCC_IS_INPLACE(task->args) && (task->args.src.info.mem_type !=
                                        task->args.dst.info.mem_type)) {
        tl_error(UCC_TL_TEAM_LIB(task->team),
                 "assymetric src/dst memory types are not supported yetpp");
        return UCC_ERR_NOT_SUPPORTED;
    }

    /* Set sync information for DPU */
    task->put_sync.coll_id           = team->coll_id;
    task->put_sync.dtype             = coll_args->src.info.datatype;
    task->put_sync.count_total       = coll_args->src.info.count;
    task->put_sync.coll_type         = coll_args->coll_type;
    task->get_sync.coll_id           = 0;
    task->get_sync.count_serviced    = 0;

    memset(&task->task_reqs.req_param, 0, sizeof(ucp_request_param_t));
    task->super.post     = ucc_tl_dpu_alltoall_start;
    task->super.progress = ucc_tl_dpu_alltoall_progress;

    return UCC_OK;
}

static ucc_status_t ucc_tl_dpu_coll_finalize(ucc_coll_task_t *coll_task)
{
    ucc_tl_dpu_task_t *task = ucc_derived_of(coll_task, ucc_tl_dpu_task_t);
    tl_info(task->team->super.super.context->lib, "finalizing task %p", task);
    ucc_tl_dpu_finalize_rkeys(task);
    ucc_tl_dpu_free_task(task);
    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_coll_init(ucc_base_coll_args_t      *coll_args,
                                         ucc_base_team_t    *team,
                                         ucc_coll_task_t    **task_h)
{
    ucc_tl_dpu_team_t    *tl_team = ucc_derived_of(team, ucc_tl_dpu_team_t);
    ucc_tl_dpu_task_t    *task    = ucc_tl_dpu_alloc_task();
    ucc_status_t          status  = UCC_OK;

    ucc_coll_task_init(&task->super, &coll_args->args, team);
    tl_info(team->context->lib, "task %p initialized", task);

    memcpy(&task->args, &coll_args->args, sizeof(ucc_coll_args_t));

    /* Misc init stuff */
    task->team                       = tl_team;
    task->super.finalize             = ucc_tl_dpu_coll_finalize;
    task->super.triggered_post       = NULL;

    /* Increase your inflight collective count */
    tl_team->coll_id++;

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
        ucc_tl_dpu_free_task(task);
        return status;
    }

    ucc_tl_dpu_init_rkeys(task);
    tl_info(team->context->lib, "init coll req %p", task);
    *task_h = &task->super;
    return status;
}

/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "tl_dpu.h"
#include "../../../core/ucc_team.h"
#include "tl_dpu_coll.h"
#include "coll_score/ucc_coll_score.h"

ucc_status_t ucc_tl_dpu_new_team_create_test(ucc_tl_dpu_team_t *team, int rail)
{
    ucc_tl_dpu_context_t    *ctx = UCC_TL_DPU_TEAM_CTX(team);
    ucc_team_t              *ucc_team = team->super.super.params.team;
    ucc_status_t            ucc_status = UCC_OK;

    /* notify dpu processes to mirror this team on the DPU world */

    if (ucc_team->ctx_ranks == NULL) {
        team->status = UCC_INPROGRESS;
        return team->status;
    }

    ucc_tl_dpu_rkey_t *rank_list_rkey = &team->dpu_sync_list[rail].ctx_rank_rkey;

    ucc_tl_dpu_put_sync_t              team_mirroring_signal;
    ucs_status_ptr_t                   team_mirroring_signal_req;
    ucp_request_param_t                team_mirror_req_param = {0};

    ctx->dpu_ctx_list[rail].coll_id_issued++;
    team->dpu_sync_list[rail].coll_id_issued = ctx->dpu_ctx_list[rail].coll_id_issued;

    team_mirroring_signal.create_new_team      = 1;
    team_mirroring_signal.coll_id              = ctx->dpu_ctx_list[rail].coll_id_issued;
    team_mirroring_signal.coll_type            = UCC_COLL_TYPE_LAST;
    team_mirroring_signal.dtype                = UCC_DT_USERDEFINED;
    team_mirroring_signal.op                   = UCC_OP_USERDEFINED;
    team_mirroring_signal.team_id              = ucc_team->id;

    /* register the rank list in world with hca and give its rdma
     * key/address to dpu*/
    team_mirroring_signal.rkeys.rank_list = ucc_team->ctx_ranks;
    
    team_mirroring_signal.rkeys.rank_list_rkey_len = team->size *
        sizeof(ucc_rank_t);

    ucc_status = ucc_tl_dpu_register_buf(ctx->dpu_ctx_list[rail].ucp_context,
            team_mirroring_signal.rkeys.rank_list,
            team_mirroring_signal.rkeys.rank_list_rkey_len,
            rank_list_rkey);

    if (UCC_OK != ucc_status) {
        goto err;
    }

    memcpy(team_mirroring_signal.rkeys.rank_list_rkey,
            rank_list_rkey->rkey_buf, rank_list_rkey->rkey_buf_size);

    tl_info(ctx->super.super.lib, "sending team_mirroring_signal to dpu team, "
            "coll id = %u and ctx->dpu_ctx_list[%d].coll_id_completed=%d ", 
            team_mirroring_signal.coll_id, rail,
            ctx->dpu_ctx_list[rail].coll_id_completed);

    team->dpu_sync_list[rail].rem_ctrl_seg = ctx->dpu_ctx_list[rail].rem_ctrl_seg;
    team->dpu_sync_list[rail].rem_ctrl_seg_key = ctx->dpu_ctx_list[rail].rem_ctrl_seg_key;

    team_mirroring_signal_req = ucp_put_nbx(ctx->dpu_ctx_list[rail].ucp_ep,
            &team_mirroring_signal, sizeof(team_mirroring_signal),
            ctx->dpu_ctx_list[rail].rem_ctrl_seg,
            ctx->dpu_ctx_list[rail].rem_ctrl_seg_key, &team_mirror_req_param);

    if (ucc_tl_dpu_req_check(team, team_mirroring_signal_req) != UCC_OK) {
        return UCC_ERR_NO_MESSAGE;
    }

    while((ucc_tl_dpu_req_test(&team_mirroring_signal_req,
                    ctx->dpu_ctx_list[rail].ucp_worker) != UCC_OK)) {
        ucp_worker_progress(ctx->dpu_ctx_list[rail].ucp_worker);
    }
    ctx->dpu_ctx_list[rail].coll_id_completed++;
    team->dpu_sync_list[rail].coll_id_completed =
        ctx->dpu_ctx_list[rail].coll_id_completed;

    tl_info(ctx->super.super.lib, 
            "sent team_mirroring_signal to dpu team with ctx->dpu_ctx_list[%d].coll_id_completed=%d",
            rail, ctx->dpu_ctx_list[rail].coll_id_completed); 

    team->status = UCC_OK;

    return team->status;

err:
    return ucc_status;
    
}

UCC_CLASS_INIT_FUNC(ucc_tl_dpu_team_t, ucc_base_context_t *tl_context,
                    const ucc_base_team_params_t *params)
{
    ucc_status_t ucc_status = UCC_OK; 
    ucc_tl_dpu_context_t *ctx =
        ucc_derived_of(tl_context, ucc_tl_dpu_context_t);

    UCC_CLASS_CALL_SUPER_INIT(ucc_tl_team_t, &ctx->super, params);

    tl_info(ctx->super.super.lib, "starting: %p team_create", self);

    ucp_request_param_t req_param = {0};
    int tc_poll = UCC_TL_DPU_TC_POLL, i, rail = 0;
    size_t total_rkey_size = 0;
    ucc_tl_dpu_sync_t *dpu_sync = NULL;
    ucc_tl_dpu_connect_t *dpu_connect = NULL;
    
    self->size      = UCC_TL_TEAM_SIZE(self);
    self->rank      = UCC_TL_TEAM_RANK(self);
    self->status    = UCC_OPERATION_INITIALIZED;
    self->dpu_per_node_cnt = ctx->dpu_per_node_cnt;

    assert(self->dpu_per_node_cnt > 0);

    for (rail = 0; rail < self->dpu_per_node_cnt; rail++) {
        
        dpu_sync = &self->dpu_sync_list[rail];
        dpu_connect = &ctx->dpu_ctx_list[rail];

        dpu_sync->ctx_rank_rkey.rkey_buf_size = 0;
        dpu_sync->coll_id_issued              = 0;
        dpu_sync->coll_id_completed           = 0;
        dpu_sync->status                      = UCC_OPERATION_INITIALIZED;

        /*  avoid preparing the get_sync for teams other than world */
        if (params->id != 1) {
            ucc_status =  ucc_tl_dpu_new_team_create_test(self, rail);
            if (ucc_status != UCC_OK) {
                return ucc_status;
            }
            continue;
        }

        dpu_sync->conn_buf  = ucc_malloc(sizeof(ucc_tl_dpu_conn_buf_t),
                            "Allocate connection buffer");
        dpu_sync->conn_buf->mmap_params.field_mask =
                                    UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                                    UCP_MEM_MAP_PARAM_FIELD_LENGTH;
        dpu_sync->conn_buf->mmap_params.address = (void*)&dpu_connect->get_sync;
        dpu_sync->conn_buf->mmap_params.length = sizeof(ucc_tl_dpu_get_sync_t);

        ucc_status = ucs_status_to_ucc_status(
                ucp_mem_map(dpu_connect->ucp_context, &dpu_sync->conn_buf->mmap_params,
                            &dpu_sync->get_sync_memh));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        ucc_status = ucs_status_to_ucc_status(
            ucp_rkey_pack(dpu_connect->ucp_context, dpu_sync->get_sync_memh,
                          &dpu_sync->conn_buf->get_sync_rkey_buf,
                          &dpu_sync->conn_buf->get_sync_rkey_buf_size));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->rem_data_in = ucc_calloc(1, sizeof(uint64_t));
        dpu_sync->rem_data_out = ucc_calloc(1, sizeof(uint64_t));

        dpu_sync->send_req[0] = ucp_tag_send_nbx(dpu_connect->ucp_ep,
                                        &dpu_sync->conn_buf->mmap_params.address,
                                        sizeof(uint64_t),
                                        UCC_TL_DPU_EXCHANGE_ADDR_TAG,
                                        &req_param);
        ucc_status = ucc_tl_dpu_req_check(self, dpu_sync->send_req[0]);
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->send_req[1] = ucp_tag_send_nbx(dpu_connect->ucp_ep,
                                        &dpu_sync->conn_buf->get_sync_rkey_buf_size,
                                        sizeof(size_t),
                                        UCC_TL_DPU_EXCHANGE_LENGTH_TAG,
                                        &req_param);
        ucc_status = ucc_tl_dpu_req_check(self, dpu_sync->send_req[1]);
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->send_req[2] = ucp_tag_send_nbx(dpu_connect->ucp_ep,
                                        dpu_sync->conn_buf->get_sync_rkey_buf,
                                        dpu_sync->conn_buf->get_sync_rkey_buf_size,
                                        UCC_TL_DPU_EXCHANGE_RKEY_TAG,
                                        &req_param);
        ucc_status = ucc_tl_dpu_req_check(self, dpu_sync->send_req[2]);
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->recv_req[0] = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                                    dpu_sync->conn_buf->rem_rkeys_lengths,
                                    sizeof(dpu_sync->conn_buf->rem_rkeys_lengths),
                                    UCC_TL_DPU_EXCHANGE_LENGTH_TAG, (uint64_t)-1,
                                    &req_param);
        ucc_status = ucc_tl_dpu_req_check(self, dpu_sync->recv_req[0]);
        if (UCC_OK != ucc_status) {
            goto err;
        }

        for (i = 0; i < tc_poll; i++) {
            ucp_worker_progress(dpu_connect->ucp_worker);
            if ((ucc_tl_dpu_req_test(&(dpu_sync->send_req[0]),
                            dpu_connect->ucp_worker) == UCC_OK) &&
                (ucc_tl_dpu_req_test(&(dpu_sync->send_req[1]),
                                     dpu_connect->ucp_worker) == UCC_OK) &&
                (ucc_tl_dpu_req_test(&(dpu_sync->send_req[2]),
                                     dpu_connect->ucp_worker) == UCC_OK) &&
                (ucc_tl_dpu_req_test(&(dpu_sync->recv_req[0]),
                                     dpu_connect->ucp_worker) == UCC_OK))
            {
                dpu_sync->status = UCC_INPROGRESS; /* Advance connection establishment */
                break;
            }
        }

        if (UCC_INPROGRESS != dpu_sync->status) {
            ucc_status = UCC_OK;
            continue;
        }

        ucp_rkey_buffer_release(dpu_sync->conn_buf->get_sync_rkey_buf);
        dpu_sync->conn_buf->get_sync_rkey_buf = NULL;

        total_rkey_size     = dpu_sync->conn_buf->rem_rkeys_lengths[0] +
                              dpu_sync->conn_buf->rem_rkeys_lengths[1] +
                              dpu_sync->conn_buf->rem_rkeys_lengths[2];
        dpu_sync->conn_buf->rem_rkeys = ucc_malloc(total_rkey_size, "rem_rkeys alloc");
        dpu_sync->recv_req[1]   = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                                        &dpu_sync->conn_buf->rem_addresses,
                                        sizeof(dpu_sync->conn_buf->rem_addresses),
                                        UCC_TL_DPU_EXCHANGE_ADDR_TAG, (uint64_t)-1,
                                        &req_param);
        if (ucc_tl_dpu_req_check(self, dpu_sync->recv_req[1]) != UCC_OK) {
            goto err;
        }

        dpu_sync->recv_req[2] = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                dpu_sync->conn_buf->rem_rkeys, total_rkey_size,
                UCC_TL_DPU_EXCHANGE_RKEY_TAG, (uint64_t)-1, &req_param);
        if (ucc_tl_dpu_req_check(self, dpu_sync->recv_req[2]) != UCC_OK) {
            goto err;
        }

        for (i = 0; i < tc_poll; i++) {
            ucp_worker_progress(dpu_connect->ucp_worker);
            if ((ucc_tl_dpu_req_test(&dpu_sync->recv_req[1], dpu_connect->ucp_worker) == UCC_OK) &&
                (ucc_tl_dpu_req_test(&dpu_sync->recv_req[2], dpu_connect->ucp_worker) == UCC_OK))
            {
                dpu_sync->status = UCC_OK;
                break;
            }
        }

        if (UCC_OK != dpu_sync->status) {
            ucc_status = UCC_OK;
            continue;
        }

        dpu_sync->rem_ctrl_seg = dpu_sync->conn_buf->rem_addresses[0];
        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep, dpu_sync->conn_buf->rem_rkeys,
                                &dpu_sync->rem_ctrl_seg_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->rem_data_in[0] = dpu_sync->conn_buf->rem_addresses[1];
        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep,
                        (void*)((ptrdiff_t)dpu_sync->conn_buf->rem_rkeys +
                        dpu_sync->conn_buf->rem_rkeys_lengths[0]),
                        &dpu_sync->rem_data_in_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        dpu_sync->rem_data_out[0] = dpu_sync->conn_buf->rem_addresses[2];
        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep,
                                (void*)((ptrdiff_t)dpu_sync->conn_buf->rem_rkeys +
                                dpu_sync->conn_buf->rem_rkeys_lengths[1] +
                                dpu_sync->conn_buf->rem_rkeys_lengths[0]),
                           &dpu_sync->rem_data_out_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        ucc_free(dpu_sync->conn_buf->rem_rkeys);
        dpu_sync->conn_buf->rem_rkeys = NULL;
        ucc_free(dpu_sync->conn_buf);


        for (i=0; i<3; i++) {
            if (dpu_sync->send_req[i]) {
                ucp_request_free(dpu_sync->send_req[i]);
            }
            if (dpu_sync->recv_req[i]) {
                ucp_request_free(dpu_sync->recv_req[i]);
            }
        }

        if (dpu_sync->status == UCC_OK) {
            dpu_connect->rem_ctrl_seg = dpu_sync->conn_buf->rem_addresses[0];
            dpu_connect->rem_ctrl_seg_key = dpu_sync->rem_ctrl_seg_key; 
        }
    }

    /* Make sure all the DPUs are done */
    self->status = UCC_OK;
    for (rail = 0; rail < self->dpu_per_node_cnt; rail++) {
        if (self->dpu_sync_list[rail].status != UCC_OK) {
            self->status = self->dpu_sync_list[rail].status;
            if (self->dpu_sync_list[rail].status == UCC_OPERATION_INITIALIZED) {
                break;
            } 
        }
    }

    return self->status;
err:
    for (i = 0; i <= rail; i++) {
        if (rail == self->dpu_per_node_cnt) break;
        if (self->dpu_sync_list[i].conn_buf->rem_rkeys) {
            ucc_free(self->dpu_sync_list[i].conn_buf->rem_rkeys);
        }
        if (self->dpu_sync_list[i].conn_buf->get_sync_rkey_buf) {
            ucp_rkey_buffer_release(self->dpu_sync_list[i].conn_buf->get_sync_rkey_buf);
            self->dpu_sync_list[i].conn_buf->get_sync_rkey_buf = NULL;
        }
        ucc_free(self->dpu_sync_list[i].conn_buf);
    }

    return ucc_status;
}

UCC_CLASS_CLEANUP_FUNC(ucc_tl_dpu_team_t)
{
    tl_info(self->super.super.context->lib, "finalizing tl team: %p", self);
}

UCC_CLASS_DEFINE_DELETE_FUNC(ucc_tl_dpu_team_t, ucc_base_team_t);
UCC_CLASS_DEFINE(ucc_tl_dpu_team_t, ucc_tl_team_t);

ucc_status_t ucc_tl_dpu_team_destroy(ucc_base_team_t *tl_team)
{
    ucc_tl_dpu_team_t           *team = ucc_derived_of(tl_team, ucc_tl_dpu_team_t);
    ucc_tl_dpu_context_t        *ctx = UCC_TL_DPU_TEAM_CTX(team);
    uint16_t                    team_id = tl_team->params.id;
    ucc_tl_dpu_put_sync_t       hangup;
    ucs_status_ptr_t            hangup_req;
    ucp_request_param_t         req_param = {0};

    /* Send notification to dpu for releasing the mirroring team on
     * dpu world (if it is releasing a subcomm's team) or ask dpu to 
     * finalize (if it is releasing comm world'd team) */

    hangup.coll_id      = ++ctx->coll_id_issued;
    team->coll_id_issued = ctx->coll_id_issued;
    hangup.coll_type    = UCC_COLL_TYPE_LAST;
    hangup.dtype        = UCC_DT_USERDEFINED;
    hangup.op           = UCC_OP_USERDEFINED;
    hangup.team_id      = team_id;
    hangup.create_new_team = 0;
 
    tl_info(ctx->super.super.lib, "sending hangup/team_free to dpu team, coll id = %u", hangup.coll_id);
    hangup_req = ucp_put_nbx(ctx->ucp_ep, &hangup, sizeof(hangup),
                             team->rem_ctrl_seg, team->rem_ctrl_seg_key,
                             &req_param);
    if (ucc_tl_dpu_req_check(team, hangup_req) != UCC_OK) {
        return UCC_ERR_NO_MESSAGE;
    }
    while((ucc_tl_dpu_req_test(&hangup_req, ctx->ucp_worker) != UCC_OK)) {
        ucp_worker_progress(ctx->ucp_worker);
    }
    tl_info(ctx->super.super.lib, "sent hangup/team_free to dpu team");

    ucp_request_param_t param = {};
    ucs_status_ptr_t request = ucp_worker_flush_nbx(ctx->ucp_worker, &param);
    while((ucc_tl_dpu_req_test(&request, ctx->ucp_worker) != UCC_OK)) {
        ucp_worker_progress(ctx->ucp_worker);
    }
 
    if (team_id != 1) {
        /* destroying a team for a sub comm other than world  */
        ucc_tl_dpu_deregister_buf(ctx->ucp_context, &team->ctx_rank_rkey);
        fprintf(stderr, "destroyed a subcomm dpu team with  team_id=%d \n",
                team_id);
    } else {
        /* It is destroying the world team */
        ucp_rkey_destroy(team->rem_ctrl_seg_key);
        ucp_rkey_destroy(team->rem_data_in_key);
        ucp_rkey_destroy(team->rem_data_out_key);
        ucp_mem_unmap(ctx->ucp_context, team->get_sync_memh);

        ucc_free(team->rem_data_in);
        ucc_free(team->rem_data_out);
    }

    if (hangup_req) {
        ucp_request_free(hangup_req);
    }
    
    ctx->coll_id_completed++;
    team->coll_id_completed = ctx->coll_id_completed;
    UCC_CLASS_DELETE_FUNC_NAME(ucc_tl_dpu_team_t)(tl_team);

    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_team_create_test(ucc_base_team_t *tl_team)
{
    ucc_tl_dpu_team_t       *team = ucc_derived_of(tl_team, ucc_tl_dpu_team_t);
    ucc_tl_dpu_context_t    *ctx = UCC_TL_DPU_TEAM_CTX(team);
    ucc_status_t            ucc_status = UCC_OK;
    int                     tc_poll = UCC_TL_DPU_TC_POLL, i = 0, rail;
    size_t                  total_rkey_size;
    ucp_request_param_t     req_param = {0};
    ucc_tl_dpu_sync_t       *dpu_sync = NULL;
    ucc_tl_dpu_connect_t    *dpu_connect = NULL;

    if (UCC_OK == team->status) {
        return UCC_OK;
    }

    for (rail = 0; rail < team->dpu_per_node_cnt; rail++) {

        dpu_sync = &team->dpu_sync_list[rail];
        dpu_connect = &ctx->dpu_ctx_list[rail];

        if (UCC_OK == dpu_sync->status) {
            continue;
        }

        if (UCC_OPERATION_INITIALIZED == dpu_sync->status) {
            for (i = 0; i < tc_poll; i++) {
                ucp_worker_progress(dpu_connect->ucp_worker);
                if ((ucc_tl_dpu_req_test(&dpu_sync->send_req[0],
                                dpu_connect->ucp_worker) == UCC_OK) &&
                    (ucc_tl_dpu_req_test(&dpu_sync->send_req[1],
                                         dpu_connect->ucp_worker) == UCC_OK) &&
                    (ucc_tl_dpu_req_test(&dpu_sync->send_req[2],
                                         dpu_connect->ucp_worker) == UCC_OK) &&
                    (ucc_tl_dpu_req_test(&dpu_sync->recv_req[0],
                                         dpu_connect->ucp_worker) == UCC_OK))
                {
                    dpu_sync->status = UCC_INPROGRESS; /* Advance connection establishment */
                    break;
                }
            }

            if (UCC_INPROGRESS != dpu_sync->status) {
                ucc_status = UCC_INPROGRESS;
                continue;
            }

            /* Continue connection establishment */
            ucp_rkey_buffer_release(dpu_sync->conn_buf->get_sync_rkey_buf);
            dpu_sync->conn_buf->get_sync_rkey_buf = NULL;

            total_rkey_size = dpu_sync->conn_buf->rem_rkeys_lengths[0] +
                              dpu_sync->conn_buf->rem_rkeys_lengths[1] +
                              dpu_sync->conn_buf->rem_rkeys_lengths[2];
            dpu_sync->conn_buf->rem_rkeys = ucc_malloc(total_rkey_size, "rem_rkeys alloc");

            dpu_sync->recv_req[0] = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                                &dpu_sync->conn_buf->rem_addresses,
                                sizeof(dpu_sync->conn_buf->rem_addresses),
                                UCC_TL_DPU_EXCHANGE_ADDR_TAG, (uint64_t)-1,
                                &req_param);
            if (ucc_tl_dpu_req_check(team, dpu_sync->recv_req[0]) != UCC_OK) {
                goto err;
            }

            dpu_sync->recv_req[1] = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                                dpu_sync->conn_buf->rem_rkeys,
                                total_rkey_size,
                                UCC_TL_DPU_EXCHANGE_RKEY_TAG, (uint64_t)-1,
                                &req_param);
            if (ucc_tl_dpu_req_check(team, dpu_sync->recv_req[1]) != UCC_OK) {
                goto err;
            }

            for (i = 0; i < tc_poll; i++) {
                ucp_worker_progress(dpu_connect->ucp_worker);
                if ((ucc_tl_dpu_req_test(&dpu_sync->recv_req[0], dpu_connect->ucp_worker) == UCC_OK) &&
                    (ucc_tl_dpu_req_test(&dpu_sync->recv_req[1], dpu_connect->ucp_worker) == UCC_OK))
                {
                    dpu_sync->status = UCC_OK;
                    break;
                }
            }
            if (UCC_OK != dpu_sync->status) {
                ucc_status = UCC_INPROGRESS;
                continue;
            }
        }

        if (UCC_INPROGRESS == dpu_sync->status) {
            for (i = 0; i < tc_poll; i++) {
                ucp_worker_progress(dpu_connect->ucp_worker);
                if ((ucc_tl_dpu_req_test(&dpu_sync->recv_req[0], dpu_connect->ucp_worker) == UCC_OK) &&
                    (ucc_tl_dpu_req_test(&dpu_sync->recv_req[1], dpu_connect->ucp_worker) == UCC_OK))
                {
                    dpu_sync->status = UCC_OK;
                    break;
                }
            }
            if (UCC_OK != dpu_sync->status) {
                ucc_status = UCC_INPROGRESS;
                continue;
            }
        }

        dpu_sync->rem_ctrl_seg = dpu_sync->conn_buf->rem_addresses[0];
        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep, dpu_sync->conn_buf->rem_rkeys,
                                &dpu_sync->rem_ctrl_seg_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }
        dpu_sync->rem_data_in[0] = dpu_sync->conn_buf->rem_addresses[1];

        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep,
                        (void*)((ptrdiff_t)dpu_sync->conn_buf->rem_rkeys +
                        dpu_sync->conn_buf->rem_rkeys_lengths[0]),
                        &dpu_sync->rem_data_in_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }
        dpu_sync->rem_data_out[0] = dpu_sync->conn_buf->rem_addresses[2];

        ucc_status = ucs_status_to_ucc_status(
            ucp_ep_rkey_unpack(dpu_connect->ucp_ep,
                                (void*)((ptrdiff_t)dpu_sync->conn_buf->rem_rkeys +
                                dpu_sync->conn_buf->rem_rkeys_lengths[1] +
                                dpu_sync->conn_buf->rem_rkeys_lengths[0]),
                           &dpu_sync->rem_data_out_key));
        if (UCC_OK != ucc_status) {
            goto err;
        }

        ucc_free(dpu_sync->conn_buf->rem_rkeys);
        dpu_sync->conn_buf->rem_rkeys = NULL;
        ucc_free(dpu_sync->conn_buf);

        for (i=0; i<3; i++) {
            if (dpu_sync->send_req[i]) {
                ucp_request_free(dpu_sync->send_req[i]);
            }
            if (dpu_sync->recv_req[i]) {
                //ucp_request_free(dpu_sync->recv_req[i]);
            }
        }

        if (dpu_sync->status == UCC_OK) {
            dpu_connect->rem_ctrl_seg = dpu_sync->conn_buf->rem_addresses[0];
            dpu_connect->rem_ctrl_seg_key = dpu_sync->rem_ctrl_seg_key; 
        }
    }

    /* Make sure all the DPUs are done */
    team->status = UCC_OK;
    for (rail = 0; rail < team->dpu_per_node_cnt; rail++) {
        if (team->dpu_sync_list[rail].status != UCC_OK) {
            team->status = team->dpu_sync_list[rail].status;
            if (team->dpu_sync_list[rail].status == UCC_OPERATION_INITIALIZED) {
                break;
            } 
        }
    }

    return team->status;
err:

    for (i = 0; i <= rail; i++) {
        if (rail == team->dpu_per_node_cnt) break;
        if (team->dpu_sync_list[i].conn_buf->rem_rkeys) {
            ucc_free(team->dpu_sync_list[i].conn_buf->rem_rkeys);
        }
        if (team->dpu_sync_list[i].conn_buf->get_sync_rkey_buf) {
            ucp_rkey_buffer_release(team->dpu_sync_list[i].conn_buf->get_sync_rkey_buf);
            team->dpu_sync_list[i].conn_buf->get_sync_rkey_buf = NULL;
        }
        ucc_free(team->dpu_sync_list[i].conn_buf);
    }
    return ucc_status;
}

ucc_status_t ucc_tl_dpu_team_get_scores(ucc_base_team_t   *tl_team,
                                         ucc_coll_score_t **score_p)
{
    ucc_tl_dpu_team_t  *team = ucc_derived_of(tl_team, ucc_tl_dpu_team_t);
    ucc_tl_dpu_lib_t   *lib  = UCC_TL_DPU_TEAM_LIB(team);
    ucc_coll_score_t   *score;
    ucc_status_t        status;

    /* There can be a different logic for different coll_type/mem_type.
       Right now just init everything the same way. */
    status = ucc_coll_score_build_default(tl_team, UCC_TL_DPU_DEFAULT_SCORE,
                           ucc_tl_dpu_coll_init, UCC_TL_DPU_SUPPORTED_COLLS,
                           NULL, 0, &score);
    if (UCC_OK != status) {
        return status;
    }
    if (strlen(lib->super.super.score_str) > 0) {
        status = ucc_coll_score_update_from_str(lib->super.super.score_str,
                                                score, team->size,
                                                ucc_tl_dpu_coll_init, &team->super.super,
                                                UCC_TL_DPU_DEFAULT_SCORE,
                                                NULL);
        if (status == UCC_ERR_INVALID_PARAM) {
            /* User provided incorrect input - try to proceed */
            goto err;
        }
    }
    *score_p = score;
    return status;
err:
    ucc_coll_score_free(score);
    return status;
}

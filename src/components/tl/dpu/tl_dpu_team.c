/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <assert.h>
#include "tl_dpu.h"
#include "../../../core/ucc_team.h"
#include "tl_dpu_coll.h"
#include "coll_score/ucc_coll_score.h"
#include "../../../core/ucc_service_coll.h"

#define UCC_WORLD_TEAM_ID 32768

static ucc_status_t _dpu_client_oob_allgather(ucc_tl_dpu_team_t *team, int num_colls, size_t *msg_lens)
{
    ucc_tl_dpu_context_t *ctx = UCC_TL_DPU_TEAM_CTX(team);
    ucc_team_t *ucc_team = team->super.super.params.team;

    ucp_request_param_t req_param = {0};
    ucp_tag_t req_tag = 0, tag_mask = 0; 
    ucs_status_ptr_t req;
    ucc_rank_t team_size = team->size;
    ucc_subset_t subset = {.map.type   = UCC_EP_MAP_FULL,
                           .map.ep_num = team->size,
                           .myrank     = team->rank};

    for (int i=0; i<num_colls; i++) {
        size_t in_len = msg_lens[i];
        size_t out_len = in_len * team_size;
        char *tmp_buf = ucc_malloc(out_len);
        for (int rail = 0; rail < ctx->dpu_per_node_cnt; rail++) {
            ucc_tl_dpu_connect_t *dpu_connect = &ctx->dpu_ctx_list[rail];
            ucp_worker_fence(dpu_connect->ucp_worker);
            req = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                    tmp_buf, in_len, req_tag, tag_mask, &req_param);
            ucc_tl_dpu_req_wait(dpu_connect->ucp_worker, req);
            tl_debug(ctx->super.super.lib,
                    "oob_allgather received %zu bytes\n", in_len);

            ucc_service_coll_req_t *request;
            ucc_service_allgather(ucc_team, tmp_buf, tmp_buf, in_len, subset, &request);
            while (UCC_OK != ucc_service_coll_test(request)) {};
            ucc_service_coll_finalize(request);

            req = ucp_tag_send_nbx(dpu_connect->ucp_ep,
                    tmp_buf, out_len, req_tag, &req_param);
            ucc_tl_dpu_req_wait(dpu_connect->ucp_worker, req);
            tl_debug(ctx->super.super.lib,
                    "oob_allgather sent %zu bytes\n", out_len);

            ucp_worker_flush(dpu_connect->ucp_worker);
        }
        ucc_free(tmp_buf);
    }

    tl_info(ctx->super.super.lib,
            "Performed %d allgathers on behalf of DPU\n", num_colls); 
    return UCC_OK;
}

/* Wait for initilization completion notification from dpu */
static ucc_status_t _dpu_init_completion_wait(ucc_tl_dpu_team_t *team)
{
    int rail;
    ucp_request_param_t req_param = {0};
    ucp_tag_t req_tag = 0, tag_mask = 0; 
    ucc_tl_dpu_get_sync_t get_sync = {0};
    ucs_status_ptr_t recv_req;
    ucc_tl_dpu_connect_t *dpu_connect;
    ucc_tl_dpu_context_t    *ctx = UCC_TL_DPU_TEAM_CTX(team);

    for (rail = 0; rail < ctx->dpu_per_node_cnt; rail++) {
        dpu_connect = &ctx->dpu_ctx_list[rail];
        ucp_worker_fence(dpu_connect->ucp_worker);
        recv_req = ucp_tag_recv_nbx(dpu_connect->ucp_worker,
                &get_sync, sizeof(ucc_tl_dpu_get_sync_t),
                req_tag, tag_mask, &req_param);
        ucc_tl_dpu_req_wait(dpu_connect->ucp_worker, recv_req);
    }

    tl_info(ctx->super.super.lib,
            "Received completion notification from all DPU rails\n");

    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_new_team_create_test(ucc_tl_dpu_team_t *team, int rail)
{
    ucc_tl_dpu_context_t    *ctx = UCC_TL_DPU_TEAM_CTX(team);
    ucc_team_t              *ucc_team = team->super.super.params.team;

    /* notify dpu processes to mirror this team on the DPU world */

    if (ucc_team->ctx_ranks == NULL) {
        team->status = UCC_INPROGRESS;
        return team->status;
    }

    ucc_tl_dpu_put_sync_t              team_mirroring_signal;
    ucs_status_ptr_t                   team_mirroring_signal_req;
    ucp_request_param_t                team_mirror_req_param = {0};

    ctx->dpu_ctx_list[rail].coll_id_issued++;
    team->dpu_sync_list[rail].coll_id_issued = ctx->dpu_ctx_list[rail].coll_id_issued;

    team_mirroring_signal.create_new_team      = 1;
    team_mirroring_signal.coll_id              = ctx->dpu_ctx_list[rail].coll_id_issued;
    team_mirroring_signal.coll_args.coll_type  = UCC_COLL_TYPE_LAST;
    team_mirroring_signal.team_id              = ucc_team->id;
    team_mirroring_signal.dpu_per_node_cnt     = ctx->dpu_per_node_cnt;

    /* register the rank list in world with hca and give its rdma
     * key/address to dpu*/
    team_mirroring_signal.num_ranks = team->size;
    team_mirroring_signal.host_team_rank = team->rank;
    memcpy(team_mirroring_signal.rank_list, ucc_team->ctx_ranks, team->size * sizeof(ucc_rank_t));

    tl_info(ctx->super.super.lib, "sending team_mirroring_signal to dpu team, "
            "coll id = %u and ctx->dpu_ctx_list[%d].coll_id_completed=%d ", 
            team_mirroring_signal.coll_id, rail,
            ctx->dpu_ctx_list[rail].coll_id_completed);

    team_mirroring_signal_req = ucp_tag_send_nbx(
            ctx->dpu_ctx_list[rail].ucp_ep,
            &team_mirroring_signal, sizeof(team_mirroring_signal),
            0, &team_mirror_req_param);

    if (ucc_tl_dpu_req_check(team, team_mirroring_signal_req) != UCC_OK) {
        return UCC_ERR_NO_MESSAGE;
    }
    ucc_tl_dpu_req_wait(ctx->dpu_ctx_list[rail].ucp_worker, team_mirroring_signal_req);

    team->dpu_sync_list[rail].coll_id_completed = ++ctx->dpu_ctx_list[rail].coll_id_completed;

    tl_info(ctx->super.super.lib, 
            "sent team_mirroring_signal to dpu team with ctx->dpu_ctx_list[%d].coll_id_completed=%d",
            rail, ctx->dpu_ctx_list[rail].coll_id_completed); 

    team->status = UCC_OK;
    return team->status;
}

UCC_CLASS_INIT_FUNC(ucc_tl_dpu_team_t, ucc_base_context_t *tl_context,
                    const ucc_base_team_params_t *params)
{
    ucc_status_t ucc_status = UCC_OK;// status = UCC_INPROGRESS; 
    ucc_tl_dpu_context_t *ctx =
        ucc_derived_of(tl_context, ucc_tl_dpu_context_t);

    UCC_CLASS_CALL_SUPER_INIT(ucc_tl_team_t, &ctx->super, params);

    tl_info(ctx->super.super.lib, "starting: %p team_create team_id %d", self, params->id);

    self->size      = UCC_TL_TEAM_SIZE(self);
    self->rank      = UCC_TL_TEAM_RANK(self);
    self->status    = UCC_INPROGRESS;
    self->dpu_per_node_cnt = ctx->dpu_per_node_cnt;
    assert(self->dpu_per_node_cnt > 0);

    for (int rail = 0; rail < self->dpu_per_node_cnt; rail++) {
        ucc_tl_dpu_sync_t *dpu_sync   = &self->dpu_sync_list[rail];
        dpu_sync->coll_id_issued      = 0;
        dpu_sync->coll_id_completed   = 0;
        dpu_sync->status              = UCC_OPERATION_INITIALIZED;

        /* Execute oob allgather on behalf of DPU */
        if (params->id == UCC_WORLD_TEAM_ID) {
            int    num_colls   = 4;
            size_t msg_lens[4] = {8, 128, 8, 128};
            _dpu_client_oob_allgather(self, num_colls, msg_lens);
            _dpu_init_completion_wait(self);
        }

        /*  avoid preparing the get_sync for teams other than world */
        if (params->id != UCC_WORLD_TEAM_ID) {
            ucc_status =  ucc_tl_dpu_new_team_create_test(self, rail);
            if (ucc_status != UCC_OK) {
                return ucc_status;
            }
            if (rail == self->dpu_per_node_cnt - 1) {
                return ucc_status;
            } else {
                continue;
            }
        }
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
    ucp_tag_t                   req_tag = 0;
    ucc_tl_dpu_sync_t           *dpu_sync = NULL;
    ucc_tl_dpu_connect_t        *dpu_connect = NULL;
    int rail;

    /* Send notification to dpu for releasing the mirroring team on
     * dpu world (if it is releasing a subcomm's team) or ask dpu to 
     * finalize (if it is releasing comm world'd team) */

    for (rail = 0; rail < team->dpu_per_node_cnt; rail++) {

        dpu_sync = &team->dpu_sync_list[rail];
        dpu_connect = &ctx->dpu_ctx_list[rail];
        
        memset(&hangup, 0, sizeof(ucc_tl_dpu_put_sync_t));

        hangup.coll_id             = ++dpu_connect->coll_id_issued;
        dpu_sync->coll_id_issued   = dpu_connect->coll_id_issued;
        hangup.coll_args.coll_type = UCC_COLL_TYPE_LAST;
        hangup.team_id             = team_id;
        hangup.create_new_team     = 0;
     
        tl_info(ctx->super.super.lib, 
                "sending hangup/team_free to dpu dpu_sync, coll id = %u", 
                hangup.coll_id);
        hangup_req = ucp_tag_send_nbx(dpu_connect->ucp_ep,
                        &hangup, sizeof(hangup), req_tag, &req_param);
        ucc_tl_dpu_req_wait(dpu_connect->ucp_worker, hangup_req);
        tl_info(ctx->super.super.lib, "sent hangup/team_free to dpu team");

        ucs_status_ptr_t request = ucp_worker_flush_nbx(dpu_connect->ucp_worker, &req_param);
        ucc_tl_dpu_req_wait(dpu_connect->ucp_worker, request);
        dpu_sync->coll_id_completed = ++dpu_connect->coll_id_completed;

        /* Execute oob allgather on behalf of DPU */
        if (team_id == UCC_WORLD_TEAM_ID) {
            int num_colls = 2;
            size_t msg_lens[2] = {1, 1};
            _dpu_client_oob_allgather(team, num_colls, msg_lens);
        }
    }
    
    UCC_CLASS_DELETE_FUNC_NAME(ucc_tl_dpu_team_t)(tl_team);

    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_team_create_test(ucc_base_team_t *tl_team)
{
    return UCC_OK;
}

ucc_status_t ucc_tl_dpu_team_get_scores(ucc_base_team_t   *tl_team,
                                         ucc_coll_score_t **score_p)
{
    ucc_tl_dpu_team_t  *team = ucc_derived_of(tl_team, ucc_tl_dpu_team_t);
    ucc_base_context_t *ctx  = UCC_TL_TEAM_CTX(team);
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

    if (strlen(ctx->score_str) > 0) {
        status = ucc_coll_score_update_from_str(
            ctx->score_str, score, UCC_TL_TEAM_SIZE(team),
            ucc_tl_dpu_coll_init, &team->super.super,
            UCC_TL_DPU_DEFAULT_SCORE, NULL);
        /* If INVALID_PARAM - User provided incorrect input - try to proceed */
        if ((status < 0) && (status != UCC_ERR_INVALID_PARAM) &&
            (status != UCC_ERR_NOT_SUPPORTED)) {
            goto err;
        }
    }
    *score_p = score;
    return status;
err:
    ucc_coll_score_free(score);
    return status;
}

/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "server_ucc.h"
#include "host_channel.h"
#include <assert.h>

static ucc_status_t oob_allgather_test(void *req)
{
    return UCC_OK;
}

static ucc_status_t oob_allgather_free(void *req)
{
    return UCC_OK;
}

static ucc_status_t oob_allgather(void *sbuf, void *rbuf, size_t msglen,
                                   void *oob_coll_ctx, void **req)
{
    DPU_LOG("oob_allgather sbuf %p rbuf %p msglen %zu\n", sbuf, rbuf, msglen);

    dpu_ucc_global_t *g = (dpu_ucc_global_t*)oob_coll_ctx;
    dpu_hc_t *hc = g->hc;
    size_t inlen = msglen * g->hc->world_size;
    ucs_status_ptr_t request;
    ucp_tag_t req_tag = 2244, tag_mask = 0;

    request = ucp_tag_send_nbx(hc->localhost_ep,
            &msglen, sizeof(uint32_t), req_tag, &hc->req_param);
    _dpu_request_wait(hc->ucp_worker, request);

    request = ucp_tag_send_nbx(hc->localhost_ep,
            sbuf, msglen, req_tag, &hc->req_param);
    _dpu_request_wait(hc->ucp_worker, request);
    DPU_LOG("oob_allgather sent %zu bytes\n", msglen);

    request = ucp_tag_recv_nbx(hc->ucp_worker,
            rbuf, inlen, req_tag, tag_mask, &hc->req_param);
    _dpu_request_wait(hc->ucp_worker, request);
    DPU_LOG("oob_allgather received %zu bytes\n", inlen);

    *req = NULL;
    return UCC_OK;
}

static ucc_status_t dpu_create_world_team(dpu_ucc_global_t *g, dpu_ucc_comm_t *comm)
{
    int world_rank = g->hc->world_rank;
    int world_size = g->hc->world_size;
    ucc_status_t status = UCC_OK;

    /* Create UCC TEAM for comm world */
    ucc_team_params_t team_params = {
        .mask   = UCC_TEAM_PARAM_FIELD_EP |
                  UCC_TEAM_PARAM_FIELD_EP_RANGE |
                  UCC_TEAM_PARAM_FIELD_EP_MAP,
        .ep     = world_rank,
        .ep_range = UCC_COLLECTIVE_EP_RANGE_CONTIG,
        .ep_map = {
            .type = UCC_EP_MAP_FULL,
            .ep_num = world_size,
        },
    };

    status = ucc_team_create_post(&comm->ctx, 1, &team_params, &comm->team);
    while (UCC_INPROGRESS == (status = ucc_team_create_test(comm->team))) {
    };
    
    return status;
}

int dpu_ucc_init(int argc, char **argv, dpu_ucc_global_t *g)
{
    ucc_status_t status;
    char *var;

    UCCCHECK_GOTO(ucc_lib_config_read("DPU_DAEMON", NULL, &g->lib_config),
                    exit_err, status);

    ucc_lib_params_t lib_params = {
        .mask = UCC_LIB_PARAM_FIELD_THREAD_MODE,
        .thread_mode = UCC_THREAD_MULTIPLE,
    };

    UCCCHECK_GOTO(ucc_init(&lib_params, g->lib_config, &g->lib),
                    free_lib_config, status);

    ucc_lib_attr_t lib_attr;
    lib_attr.mask = UCC_LIB_ATTR_FIELD_THREAD_MODE;
    UCC_CHECK(ucc_lib_get_attr(g->lib, &lib_attr));
    if (lib_attr.thread_mode != UCC_THREAD_MULTIPLE) {
        fprintf(stderr, "ucc library wasn't initialized with mt support "
                        "check ucc compile options ");
    }
free_lib_config:
    ucc_lib_config_release(g->lib_config);
exit_err:
    return status;
}

void dpu_ucc_barrier(ucc_context_h ctx, ucc_team_h team)
{
    ucc_coll_req_h request;
    ucc_coll_args_t coll = {
        .mask = 0,
        .coll_type = UCC_COLL_TYPE_BARRIER,
    };
    DPU_LOG("Issue Synchronizing Barrier on WORLD team\n");
    UCC_CHECK(ucc_collective_init(&coll, &request, team));
    UCC_CHECK(ucc_collective_post(request));
    while (UCC_OK != ucc_collective_test(request)) {
        ucc_context_progress(ctx);
    }
    UCC_CHECK(ucc_collective_finalize(request));
}

int dpu_ucc_alloc_team(dpu_ucc_global_t *g, dpu_ucc_comm_t *comm)
{
    ucc_status_t status = UCC_OK;

    /* TODO: try UCC_CONTEXT_EXCLUSIVE */
    /* Init ucc context for a specified UCC_TEST_TLS */
    ucc_context_params_t ctx_params = {
        .mask   = UCC_CONTEXT_PARAM_FIELD_TYPE |
                  UCC_CONTEXT_PARAM_FIELD_OOB,
        .type   = UCC_CONTEXT_EXCLUSIVE,
        .oob = {
            .allgather    = oob_allgather,
            .req_test     = oob_allgather_test,
            .req_free     = oob_allgather_free,
            .coll_info    = (void*)g,
            .oob_ep       = g->hc->world_rank,
            .n_oob_eps    = g->hc->world_size,
        },
    };
    ucc_context_config_h ctx_config;
    UCCCHECK_GOTO(ucc_context_config_read(g->lib, NULL, &ctx_config), free_ctx_config, status);
    UCCCHECK_GOTO(ucc_context_create(g->lib, &ctx_params, ctx_config, &comm->ctx), free_ctx, status);

    comm->g = g;
    UCCCHECK_GOTO(dpu_create_world_team(g, comm), free_ctx, status);
    comm->team_pool[UCC_WORLD_TEAM_ID] = comm->team;

    dpu_ucc_barrier(comm->ctx, comm->team);

    return status;
free_ctx:
    ucc_context_destroy(comm->ctx);
free_ctx_config:
    ucc_context_config_release(ctx_config);

    return status;
}

int dpu_ucc_free_team(dpu_ucc_global_t *g, dpu_ucc_comm_t *comm)
{
    ucc_team_destroy(comm->team);
    ucc_context_destroy(comm->ctx);
}

void dpu_ucc_finalize(dpu_ucc_global_t *g) {
    ucc_finalize(g->lib);
}

void dpu_ucc_progress(dpu_ucc_comm_t *comm)
{
    ucc_context_progress(comm->ctx);
}

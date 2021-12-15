/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "server_ucc.h"
#include "host_channel.h"
#include "ucc/api/ucc.h"

#define CORES 6
#define MAX_THREADS 128

thread_sync_t *thread_main_sync = NULL;
thread_sync_t *thread_sub_sync = NULL;
dpu_put_sync_t tmp_sync = {0};

/* TODO: export ucc_mc.h */
ucc_status_t ucc_mc_reduce(const void *src1, const void *src2, void *dst,
                           size_t count, ucc_datatype_t dtype,
                           ucc_reduction_op_t op, ucc_memory_type_t mem_type);

static void dpu_thread_set_affinity(thread_ctx_t *ctx)
{
    int i;
    int places = 6;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    if (ctx->idx >= 0) {
        for (i = 0; i < places; i+=1) {
            CPU_SET(i, &cpuset);
        }
    }
    else {
        // CPU_SET(6, &cpuset);
        CPU_SET(7, &cpuset);
    }

    pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
}

static void dpu_coll_init_alltoall(thread_ctx_t *ctx, ucc_coll_req_h *request, size_t *count_p, dpu_put_sync_t *lsync)
{
    *count_p = lsync->count_total;
    /* Multithreading not supported */
    if(ctx->idx > 0) {
        *request = NULL;
        return;
    }
    
    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLTOALL,
        .src.info = {
            .buffer   = ctx->hc->mem_segs.in.base,
            .count    = lsync->count_total,
            .datatype = lsync->dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = ctx->hc->mem_segs.out.base,
            .count    = lsync->count_total,
            .datatype = lsync->dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
    };

    UCC_CHECK(ucc_collective_init(&coll, request, ctx->comm.team));
}

static void dpu_coll_collect_host_rkeys(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* Only do in comm thread */
    assert(ctx->idx == -1);
    CTX_LOG("team id %d\n", lsync->team_id);

    int i;
    ucs_status_t status;
    ucc_coll_req_h request;
    dpu_hc_t *hc = ctx->hc;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    unsigned int team_size = 0;
    UCC_CHECK(ucc_team_get_size(team, &team_size));
    void *src_buf = &lsync->rkeys;
    void *dst_buf = hc->host_rkeys;

    assert(NULL != lsync->rkeys.src_rkey_buf);
    assert(NULL != lsync->rkeys.dst_rkey_buf);
    assert(0    <  lsync->rkeys.src_rkey_len);
    assert(0    <  lsync->rkeys.dst_rkey_len);
    assert(NULL != lsync->rkeys.src_buf);
    assert(NULL != lsync->rkeys.dst_buf);
        
    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLGATHER,
        .src.info = {
            .buffer   = src_buf,
            .count    = sizeof(host_rkey_t),
            .datatype = UCC_DT_INT8,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = dst_buf,
            .count    = sizeof(host_rkey_t) * team_size,
            .datatype = UCC_DT_INT8,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
    };

    CTX_LOG("Issue Allgather from ranks %d src %p dst %p bytes %lu\n",
            team_size, src_buf, dst_buf, sizeof(host_rkey_t));
    UCC_CHECK(ucc_collective_init(&coll, &request, team));
    UCC_CHECK(ucc_collective_post(request));
    while (UCC_OK != ucc_collective_test(request)) {
        ucc_context_progress(ctx->comm.ctx);
    }
    UCC_CHECK(ucc_collective_finalize(request));

    for (i = 0; i < team_size; i++) {
        assert(NULL != hc->host_rkeys[i].src_rkey_buf);
        assert(NULL != hc->host_rkeys[i].dst_rkey_buf);
        assert(0    <  hc->host_rkeys[i].src_rkey_len);
        assert(0    <  hc->host_rkeys[i].dst_rkey_len);
        status = ucp_ep_rkey_unpack(hc->host_eps[i], (void*)hc->host_rkeys[i].src_rkey_buf, &hc->host_src_rkeys[i]);
        assert(UCS_OK == status);
        assert(NULL != hc->host_rkeys[i].src_buf);
        status = ucp_ep_rkey_unpack(hc->host_eps[i], (void*)hc->host_rkeys[i].dst_rkey_buf, &hc->host_dst_rkeys[i]);
        assert(UCS_OK == status);
        assert(NULL != hc->host_rkeys[i].dst_buf);
        CTX_LOG("Rank %d src buf %p dst buf %p\n", i, hc->host_rkeys[i].src_buf, hc->host_rkeys[i].dst_buf);
    }

    hc->rail = lsync->rail;
    hc->dpu_per_node_cnt = lsync->dpu_per_node_cnt;
}

static void dpu_coll_do_barrier(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* Only do in comm thread */
    assert(ctx->idx == -1);

    ucs_status_t status;
    ucc_coll_req_h request;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];

    ucc_coll_args_t coll = {
        .mask = 0,
        .coll_type = UCC_COLL_TYPE_BARRIER,
    };

    CTX_LOG("Issue Synchronizing Barrier on team %d\n", lsync->team_id);
    UCC_CHECK(ucc_collective_init(&coll, &request, team));
    UCC_CHECK(ucc_collective_post(request));
    while (UCC_OK != ucc_collective_test(request)) {
        ucc_context_progress(ctx->comm.ctx);
    }
    UCC_CHECK(ucc_collective_finalize(request));
}

static void dpu_coll_free_host_rkeys(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    int i;
    unsigned int team_size = 0;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    UCC_CHECK(ucc_team_get_size(team, &team_size));
    CTX_LOG("Freeing src/dst rkeys for %u hosts\n", team_size);
    for (i = 0; i < team_size; i++) {
        ucp_rkey_destroy(ctx->hc->host_src_rkeys[i]);
        ucp_rkey_destroy(ctx->hc->host_dst_rkeys[i]);
    }
}

void dpu_waitfor_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    /* busy wait */
    while (!sync[ctx->idx].todo);
    __sync_synchronize();
    assert(!sync[ctx->idx].done);
}

void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    assert(sync[ctx->idx].todo);
    assert(!sync[ctx->idx].done);
    sync[ctx->idx].todo = 0;
    sync[ctx->idx].done = 1;
}

void dpu_waitfor_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync)
{
    int i;
    for (i = 0; i < ctx->nthreads; i++) {
        while (!sync[i].done);
    }
}

void dpu_signal_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync)
{
    int i;
    for (i = 0; i < ctx->nthreads; i++) {
        sync[i].done = 0;
    }
    __sync_synchronize();
    for (i = 0; i < ctx->nthreads; i++) {
        sync[i].todo = 1;
    }
}

void dpu_wait_for_next_coll(thread_ctx_t *ctx)
{
    CTX_LOG("Waiting for host to initiate coll id: %u\n", ctx->coll_sync.coll_id);
    dpu_hc_wait(ctx->hc, ctx->coll_sync.coll_id);
    
    memcpy(&tmp_sync, (dpu_put_sync_t*)ctx->hc->mem_segs.sync.base, sizeof(tmp_sync));
    __sync_synchronize();
}

void dpu_mark_coll_done(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    ctx->coll_sync.count_serviced = lsync->count_total;
    dpu_hc_reply(ctx->hc, &ctx->coll_sync);
}

void dpu_comm_worker(void *arg)
{
    thread_ctx_t    *tctx_pool = (thread_ctx_t *)arg;
    /* There are nthreads + 1 (main thread) in total. The last 
     * thread context in the pool is the main thread and it is consider 
     * the communication thread */
    int             nthreads = tctx_pool[0].nthreads;
    thread_ctx_t    *comm_thread_ctx = &tctx_pool[nthreads];
    thread_ctx_t    *ctx = comm_thread_ctx;
    dpu_hc_t        *hc  = ctx->hc;
    unsigned int    coll_id;     
    ucc_coll_type_t coll_type; 
    size_t          count_total; 
    uint16_t        team_id; 
    uint16_t        create_team;
    uint16_t        rail; 
    uint16_t        dpu_per_node_cnt;

    dpu_put_sync_t  *lsync = &tmp_sync; //comm_thread_ctx->hc->mem_segs.sync.base;
    ucc_status_t    status;
    assert(comm_thread_ctx->idx == -1);
    dpu_thread_set_affinity(comm_thread_ctx);
    CTX_LOG("Started comm thread\n");


    while (1) {
        comm_thread_ctx->coll_sync.coll_id++;
        comm_thread_ctx->coll_sync.count_serviced = 0;
        comm_thread_ctx->buf_idx = 0;

        CTX_LOG("Waiting for coll id: %d from host\n", ctx->coll_sync.coll_id);
        dpu_wait_for_next_coll(comm_thread_ctx);

        coll_id     = lsync->coll_id;
        coll_type   = lsync->coll_type;
        count_total = lsync->count_total;
        team_id     = lsync->team_id;
        create_team = lsync->create_new_team;
        rail        = lsync->rail;
        dpu_per_node_cnt = lsync->dpu_per_node_cnt;

        
        assert(0 <= team_id && team_id < DPU_TEAM_POOL_SIZE);
        CTX_LOG(
            "Start coll id: %u, type: %d, count total: %lu on team: %u\n",
            coll_id, coll_type, count_total, team_id);


        if (coll_type == UCC_COLL_TYPE_LAST) {
            if (create_team == 1) {
                /* signal is new comm create 
                 * mirror host team in dpu world */

                CTX_LOG("received team_mirroring_signal with comm_thread_ctx->coll_sync.coll_id = %d \n",
                        comm_thread_ctx->coll_sync.coll_id);
                
                /* 
                 *
                 * Steps: 
                 *
                 * 1. read the rank list in comm world 
                 * 2. create a new team in the dpu world 
                 * for each thread separately
                 *
                 */

                /* Step 1 */

                int i = 0;
                thread_ctx_t *ctx = &(tctx_pool[0]);
                dpu_put_sync_t * team_mirroring_signal = lsync;
                ucs_status_ptr_t status_ptr;
                ucc_team_h new_team = NULL;
                ucc_rank_t * rank_list =
                        calloc(team_mirroring_signal->rkeys.rank_list_rkey_len, 1); 
                ucp_request_param_t req_param = {0}; 

                ucp_rkey_h rkey;
                ucs_status_t rstatus;

                rstatus = ucp_ep_rkey_unpack(ctx->hc->localhost_ep,
                        (void*)team_mirroring_signal->rkeys.rank_list_rkey,
                        &rkey);

                if (rstatus != UCS_OK) {
                    printf("ucp_ep_rkey_unpack failed: %d", rstatus);
                    return;
                }


                status_ptr = ucp_get_nbx(ctx->hc->localhost_ep, rank_list,
                        team_mirroring_signal->rkeys.rank_list_rkey_len,
                        (uintptr_t)((uint64_t*)team_mirroring_signal->rkeys.rank_list),
                        rkey,
                        &req_param);

                _dpu_request_wait(ctx->hc->ucp_worker, status_ptr);

                if (status_ptr != NULL ) {
                    ucp_request_free(status_ptr);
                }
                ucp_rkey_destroy(rkey);
                
                CTX_LOG("got the rank list from host \n");

                /* Now we have the rank list in comm world available  */

                ucc_rank_t team_size =
                    team_mirroring_signal->rkeys.rank_list_rkey_len/sizeof(ucc_rank_t);

                ucc_rank_t full_size = ctx->comm.g->size;
                ucc_team_params_t      team_params;

                team_params.ep_range = UCC_COLLECTIVE_EP_RANGE_CONTIG;
                team_params.mask     = UCC_TEAM_PARAM_FIELD_EP |
                                       UCC_TEAM_PARAM_FIELD_EP_RANGE |
                                       UCC_TEAM_PARAM_FIELD_EP_MAP;

                /*  find my new rank in the new team */
                for( i = 0; i < team_size; i++) {
                    if (rank_list[i] == ctx->comm.g->rank)
                      break;
                 }
                team_params.ep = i; 

                team_params.ep_map   = ucc_ep_map_from_array(&rank_list,
                        team_size, full_size, 0);

                for (i = 0; i <= nthreads; i++) {
                    /* Step 2 */
                    ctx = &(tctx_pool[i]);
                    new_team = NULL;

                    if (UCC_OK != ucc_team_create_post(&ctx->comm.ctx, 1,
                                                       &team_params, &new_team)) {
                        /* TODO handle errors */
                        printf("ucc_team_create_post failed \n");
                        return;
                    }

                    while (UCC_INPROGRESS == (status = ucc_team_create_test(
                                    new_team))) {
                        ucc_context_progress(ctx->comm.ctx);
                    }

                    if (UCC_OK != status) {
                        /* TODO handle errors */
                        printf("ucc_team_create_test failed");
                        return;
                    }

                    /* a new team has been created, insert it into the thread context */
                    ctx->comm.team_pool[team_id] = new_team; 
                }
                
                CTX_LOG("created all the new teams  \n" );

                continue;

            } else if (team_id == 1) {

                /* World team free so Hang up */
                dpu_signal_comp_threads(comm_thread_ctx, thread_main_sync);
                dpu_mark_coll_done(comm_thread_ctx, lsync);
                break;

            } else {

                /* releasing a subcomm's team that was already created
                 * on the dpu world */

                CTX_LOG("received team_releasing_signal with "
                        "comm_thread_ctx->coll_sync.coll_id = %d and team_id ="
                        " %d \n",
                        comm_thread_ctx->coll_sync.coll_id, team_id);

                /*
                 * 1. make sure this team is not in use
                 * 2. free it and put NULL in the teams pool
                 *
                 */

                int i = 0;
                thread_ctx_t *ctx   = NULL;
                ucc_team_h new_team = NULL;
                ucc_status_t status = UCC_OK;

                for (i = 0; i <= nthreads; i++) {

                    ctx = &(tctx_pool[i]);
                    new_team = ctx->comm.team_pool[team_id]; 

                    status = UCC_INPROGRESS;
                    
                    do {
                        status = ucc_team_destroy(new_team);
                        if (status < 0) {
                            fprintf(stderr, "ucc_team_destroy failed for thread ctx %d\n",
                                    i);
                            return;
                        }
                    } while (status != UCC_OK);

                    ctx->comm.team_pool[team_id] = NULL; 
                }

                CTX_LOG("destroyed all teams with  team_id = %d \n", team_id);

                continue;
            }
        }

        if (coll_type == UCC_COLL_TYPE_ALLREDUCE) {
            dpu_coll_collect_host_rkeys(comm_thread_ctx, lsync);

            size_t dt_size   = dpu_ucc_dt_size(lsync->dtype);
            hc->pipeline.my_count  = lsync->count_total / hc->world_size;
            hc->pipeline.my_offset = hc->pipeline.my_count * dt_size * hc->world_rank;
            if (hc->world_rank == hc->world_size - 1) {
                hc->pipeline.my_count += lsync->count_total % hc->world_size;
            }

            dpu_signal_comp_threads(comm_thread_ctx, thread_main_sync);
            while (hc->pipeline.count_serviced < hc->pipeline.my_count) {
                dpu_hc_progress(comm_thread_ctx->hc, lsync, comm_thread_ctx);
            }
            dpu_hc_issue_hangup(comm_thread_ctx->hc, lsync, comm_thread_ctx);

            CTX_LOG("Waiting for worker threads to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_waitfor_comp_threads(comm_thread_ctx, thread_main_sync);

            CTX_LOG("Waiting for all ranks to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_coll_do_barrier(comm_thread_ctx, lsync);

            dpu_mark_coll_done(comm_thread_ctx, lsync);
            CTX_LOG("End coll id: %u, type: %d, count total: %lu, count serviced: %zu\n",
                    coll_id, coll_type, count_total, (size_t)comm_thread_ctx->coll_sync.count_serviced);

            dpu_coll_free_host_rkeys(comm_thread_ctx, lsync);
        }
    }
}

void *dpu_worker(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    dpu_put_sync_t *lsync = &tmp_sync; //ctx->hc->mem_segs.sync.base;
    ucc_coll_req_h request = NULL;
    size_t count_serviced;

    dpu_thread_set_affinity(ctx);

    while(1) {
        ctx->coll_sync.coll_id++;
        ctx->coll_sync.count_serviced = 0;
        ctx->buf_idx = 0;

        CTX_LOG("Waiting for coll id: %d from comm thread\n", ctx->coll_sync.coll_id);
        dpu_waitfor_comm_thread(ctx, thread_main_sync);

        unsigned int coll_id      = lsync->coll_id;
        ucc_coll_type_t coll_type = lsync->coll_type;
        ucc_datatype_t dt         = lsync->dtype;
        ucc_reduction_op_t op     = lsync->op;
        size_t count_total        = lsync->count_total;
        CTX_LOG("Start coll id: %d, type: %d, count total: %lu\n",
                coll_id, coll_type, count_total);
        
        if (coll_type == UCC_COLL_TYPE_LAST) {
            /* Hang up */
            break;
        }

        int finished = 0;
        /* Process all data */
        do {
            CTX_LOG("Waiting for more data from comm thread\n");
            dpu_waitfor_comm_thread(ctx, thread_sub_sync);
            assert(UCC_COLL_TYPE_ALLREDUCE == lsync->coll_type);

            dpu_buf_t *accbuf = thread_sub_sync->accbuf;
            dpu_buf_t *getbuf = thread_sub_sync->getbuf;
            if (accbuf == NULL && getbuf == NULL) {
                finished = 1;
                goto done;
            }
            assert(accbuf->state == REDUCING && accbuf->count > 0 && accbuf->ucp_req == NULL);
            assert(getbuf->state == REDUCING && getbuf->count > 0 && getbuf->ucp_req == NULL);

            size_t count = accbuf->count;
            ucc_mc_reduce(accbuf->buf, getbuf->buf, accbuf->buf,
                          count, dt, op, UCC_MEMORY_TYPE_HOST);
            CTX_LOG("Reduced %lu elements, serviced %lu out of %lu\n",
                    count, ctx->hc->pipeline.count_reduced, ctx->hc->pipeline.my_count);
        done:
            dpu_coll_do_barrier(ctx, lsync);
            dpu_signal_comm_thread(ctx, thread_sub_sync);

        } while (!finished);

        ctx->coll_sync.count_serviced = ctx->hc->pipeline.my_count * ctx->hc->world_size;
        CTX_LOG("End coll id: %d, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)ctx->coll_sync.count_serviced);
        dpu_signal_comm_thread(ctx, thread_main_sync);
    }
    return NULL;
}

int main(int argc, char **argv)
{
//     fprintf (stderr, "%s\n", __FUNCTION__);
//     sleep(20);
    int              nthreads = 0;
    int              i = 0;
    thread_ctx_t     *tctx_pool = NULL;
    dpu_hc_t         *hc = NULL;
    char             *env = NULL;

    dpu_ucc_global_t ucc_glob;
    dpu_hc_t         hc_b;

    if (argc < 2 ) {
        printf("Need thread # as an argument\n");
        return 1;
    }
    nthreads = atoi(argv[1]);
    if (MAX_THREADS < nthreads || 0 >= nthreads) {
        printf("ERROR: bad thread #: %d\n", nthreads);
        return 1;
    }
    printf("DPU daemon: Running with %d compute threads\n", nthreads);

    /* Need one extra thread ctx for comm thread */
    tctx_pool = calloc(nthreads+1, sizeof(*tctx_pool));
    UCC_CHECK(dpu_ucc_init(argc, argv, &ucc_glob));

    thread_main_sync = aligned_alloc(64, nthreads * sizeof(*thread_main_sync));
    memset(thread_main_sync, 0, nthreads * sizeof(*thread_main_sync));

    thread_sub_sync = aligned_alloc(64, nthreads * sizeof(*thread_sub_sync));
    memset(thread_sub_sync, 0, nthreads * sizeof(*thread_sub_sync));

    hc = &hc_b;

    UCC_CHECK(dpu_hc_init(hc));
    UCC_CHECK(dpu_hc_accept(hc));

    for(i = 0; i < nthreads; i++) {
        UCC_CHECK(dpu_ucc_alloc_team(&ucc_glob, &tctx_pool[i].comm));
        tctx_pool[i].idx      = i;
        tctx_pool[i].nthreads = nthreads;
        tctx_pool[i].hc       = hc;
        pthread_create(&tctx_pool[i].id, NULL, dpu_worker,
                       (void *)&tctx_pool[i]);
    }

    /* The final DPU worker is executed in this context */
    UCC_CHECK(dpu_ucc_alloc_team(&ucc_glob, &tctx_pool[i].comm));
    tctx_pool[i].idx      = -1;
    tctx_pool[i].nthreads = nthreads;
    tctx_pool[i].hc       = hc;
    dpu_comm_worker((void*)tctx_pool);

    for(i = 0; i < nthreads; i++) {
        pthread_join(tctx_pool[i].id, NULL);
        dpu_ucc_free_team(&ucc_glob, &tctx_pool[i].comm);
    }

    dpu_hc_finalize(hc);
    dpu_ucc_finalize(&ucc_glob);
    return 0;
}

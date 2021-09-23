/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "../../src/utils/ucc_datastruct.h" 
#include "server_ucc.h"
#include "host_channel.h"
#include "ucc/api/ucc.h"

#define CORES 6
#define MAX_THREADS 128

thread_sync_t *thread_main_sync = NULL;
thread_sync_t *thread_sub_sync = NULL;
dpu_put_sync_t tmp_sync = {0};

static void dpu_thread_set_affinity(thread_ctx_t *ctx)
{
    int i;
    int places = CORES/ctx->nthreads;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    if (ctx->idx >= 0) {
        for (i = 0; i < places; i++) {
            CPU_SET((ctx->idx * places) + i, &cpuset);
        }
    }
    else {
        CPU_SET(CORES+1, &cpuset);
    }

    pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
}

static void dpu_coll_init_allreduce(thread_ctx_t *ctx, ucc_coll_req_h *request, size_t *count_p, dpu_put_sync_t *lsync)
{
    int ar_idx = ctx->buf_idx;
    dpu_stage_t *ar_stage = &ctx->hc->pipeline.stage[ar_idx];
    assert(ar_stage->get.state == DONE);
    assert(ar_stage->ar.state  == IN_PROGRESS);
    assert(ar_stage->put.state == FREE);

    ucc_reduction_op_t op = lsync->op;
    ucc_datatype_t dtype = lsync->dtype;
    size_t dt_size = dpu_ucc_dt_size(dtype);
    size_t count = ar_stage->get.count;
    size_t block = count / ctx->nthreads;
    size_t offset = block * ctx->idx * dt_size;

    /* Do any leftover elements in the last thread */
    if (ctx->idx == ctx->nthreads - 1) {
        block += count % block;
    }
    
    void *src_buf = ar_stage->get.buf;
    void *dst_buf = ar_stage->put.buf;
    *count_p = count;
    
    CTX_LOG("Init AR idx %d src %p dst %p count %lu, block %lu, offset %lu, bytes %lu\n",
             ar_idx, src_buf, dst_buf, count, block, offset, block*dt_size);
    if (block == 0) {
        *request = NULL;
        return;
    }

    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLREDUCE,
        .mask      = UCC_COLL_ARGS_FIELD_PREDEFINED_REDUCTIONS,
        .src.info = {
            .buffer   = src_buf + offset,
            .count    = block,
            .datatype = dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = dst_buf + offset,
            .count    = block,
            .datatype = dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .reduce = {
            .predefined_op = op,
        },
    };

    UCC_CHECK(ucc_collective_init(&coll, request, ctx->comm.team_pool[lsync->team_id]));
    assert(*request != NULL);
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
    thread_ctx_t *tctx_pool = (thread_ctx_t *)arg;
    /* There is nthreads + 1 (main thread) in total. The last 
     * thread context in the pool is the main thread and it is consider 
     * the communication thread */
    int nthreads = tctx_pool[0].nthreads;
    thread_ctx_t *comm_thread_ctx = &tctx_pool[nthreads];

    dpu_put_sync_t *lsync = &tmp_sync; //comm_thread_ctx->hc->mem_segs.sync.base;
    assert(comm_thread_ctx->idx == -1);
    dpu_thread_set_affinity(comm_thread_ctx);
    ucc_status_t status;
    CTX_LOG("Started comm thread\n");


    while (1) {
        comm_thread_ctx->coll_sync.coll_id++;
        comm_thread_ctx->coll_sync.count_serviced = 0;
        comm_thread_ctx->buf_idx = 0;

        dpu_wait_for_next_coll(comm_thread_ctx);

        fprintf(stderr, "got a new task from host: lsync->coll_id=%d and lsync->team_id=%d\n",
                lsync->coll_id, lsync->team_id);
        unsigned int    coll_id     = lsync->coll_id;
        ucc_coll_type_t coll_type   = lsync->coll_type;
        size_t          count_total = lsync->count_total;
        uint16_t        team_id     = lsync->team_id;
        uint16_t        create_team = lsync->create_new_team;
        
        assert(0 <= team_id && team_id < DPU_TEAM_POOL_SIZE);
        CTX_LOG(
            "Start coll id: %u, type: %d, count total: %lu\n",
            coll_id, coll_type, count_total);

        dpu_signal_comp_threads(comm_thread_ctx, thread_main_sync);

        if (coll_type == UCC_COLL_TYPE_LAST) {
            if (create_team == 1) {
                /* signal is new comm create 
                 * mirror host team in dpu world */

                fprintf(stderr, "received team_mirroring_signal with comm_thread_ctx->coll_sync.coll_id = %d \n",
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


                /*
                 * TODO #1:
                 *
                 * 1. Create new_team for each thread (add a for loop) just like main()
                 * 
                 *
                 *
                 *
                 * */
                /*
                 * TODO #2
                 *
                 *  Steps:
                 *
                 *  1. insert into threaed context  this new team to a list of
                 *  teams that we created
                 *  2. save this new_team inside the thread context for each thread
                 *  3. use team_id to hash and find the new_team
                 *  4. how to use new_team to call allredce? --> change the
                 *  input of ucc_collective_init
                 *
                 *
                 * */

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

                rstatus = ucp_ep_rkey_unpack(ctx->hc->host_ep,
                        (void*)team_mirroring_signal->rkeys.rank_list_rkey,
                        &rkey);

                if (rstatus != UCS_OK) {
                    printf("ucp_ep_rkey_unpack failed: %d", rstatus);
                    return;
                }


                status_ptr = ucp_get_nbx(ctx->hc->host_ep, rank_list,
                        team_mirroring_signal->rkeys.rank_list_rkey_len,
                        (uintptr_t)((uint64_t*)team_mirroring_signal->rkeys.rank_list),
                        rkey,
                        &req_param);

                _dpu_request_wait(ctx->hc->ucp_worker, status_ptr);

                if (status_ptr != NULL ) {
                    ucp_request_free(status_ptr);
                }
                
                fprintf(stderr, "got the rank list from host \n");

                /* Now we have the rank list in comm world available  */

                ucc_rank_t team_size =
                    team_mirroring_signal->rkeys.rank_list_rkey_len/sizeof(ucc_rank_t);

                ucc_rank_t full_size = ctx->comm.g->size;

                ucc_team_params_t      team_params;

                team_params.ep       = ctx->comm.g->rank;
                team_params.ep_range = UCC_COLLECTIVE_EP_RANGE_CONTIG;
                team_params.mask     = UCC_TEAM_PARAM_FIELD_EP |
                                       UCC_TEAM_PARAM_FIELD_EP_RANGE |
                                       UCC_TEAM_PARAM_FIELD_EP_MAP;

                team_params.ep_map   = ucc_ep_map_from_array(&rank_list,
                        team_size, full_size, 0);

                for (i = 0; i < nthreads; i++) {
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
                
                fprintf(stderr, "created all the new teams  \n");

                continue;

        //        goto next_task;

            } else {

                /* Hang up */
                break;
            }
        }

        dpu_pipeline_t *pipe = &comm_thread_ctx->hc->pipeline;
        while (pipe->count_put.done < count_total) {
            dpu_hc_issue_get(comm_thread_ctx->hc, lsync, comm_thread_ctx);
            dpu_hc_issue_allreduce(comm_thread_ctx->hc, lsync, comm_thread_ctx);
            dpu_hc_issue_put(comm_thread_ctx->hc, lsync, comm_thread_ctx);
            dpu_hc_progress(comm_thread_ctx->hc, lsync, comm_thread_ctx);
        }

next_task:

        CTX_LOG("Waiting for worker threads to complete coll id: %u, type: %d\n", coll_id, coll_type);
        dpu_waitfor_comp_threads(comm_thread_ctx, thread_main_sync);
        dpu_mark_coll_done(comm_thread_ctx, lsync);
        CTX_LOG("End coll id: %u, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)comm_thread_ctx->coll_sync.count_serviced);
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

        dpu_waitfor_comm_thread(ctx, thread_main_sync);

        unsigned int coll_id      = lsync->coll_id;
        ucc_coll_type_t coll_type = lsync->coll_type;
        size_t count_total        = lsync->count_total;
        CTX_LOG("Start coll id: %d, type: %d, count total: %lu\n",
                coll_id, coll_type, count_total);
        
        if (coll_type == UCC_COLL_TYPE_LAST) {
            /* Hang up */
            break;
        }

        /* Process all data */
        do {
            dpu_waitfor_comm_thread(ctx, thread_sub_sync);

            if (coll_type == UCC_COLL_TYPE_ALLREDUCE) {
                dpu_coll_init_allreduce(ctx, &request, &count_serviced, lsync);
            } else if (coll_type == UCC_COLL_TYPE_ALLTOALL) {
                dpu_coll_init_alltoall(ctx, &request, &count_serviced, lsync);
            } else if (coll_type == UCC_COLL_TYPE_LAST) {
                CTX_LOG("Received hangup, exiting loop\n");
                break;
            } else {
                CTX_LOG("Unsupported coll type: %d\n", coll_type);
            }

            if (request != NULL) {
                CTX_LOG("Posting coll id: %d\n", coll_id);
                UCC_CHECK(ucc_collective_post(request));
                while (UCC_OK != ucc_collective_test(request)) {
                    ucc_context_progress(ctx->comm.ctx);
                }
                CTX_LOG("Finalizing coll id: %d\n", coll_id);
                UCC_CHECK(ucc_collective_finalize(request));
            }

            ctx->buf_idx = (ctx->buf_idx + 1) % ctx->hc->pipeline.num_buffers;
            ctx->coll_sync.count_serviced += count_serviced;

            CTX_LOG("Progressed coll id: %d, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)ctx->coll_sync.count_serviced);
            dpu_signal_comm_thread(ctx, thread_sub_sync);

        } while (ctx->coll_sync.count_serviced < count_total);

        assert(count_total == ctx->coll_sync.count_serviced);
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
    tctx_pool[i].idx      = -1;
    tctx_pool[i].nthreads = nthreads;
    tctx_pool[i].hc       = hc;
    //dpu_comm_worker((void*)&tctx_pool[i], tctx_pool);
    dpu_comm_worker((void*)tctx_pool);

    for(i = 0; i < nthreads; i++) {
        pthread_join(tctx_pool[i].id, NULL);
        dpu_ucc_free_team(&ucc_glob, &tctx_pool[i].comm);
    }

    dpu_ucc_finalize(&ucc_glob);
    return 0;
}

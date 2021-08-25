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

#define CORES 8
#define MAX_THREADS 128

thread_sync_t *thread_main_sync = NULL;
thread_sync_t *thread_sub_sync = NULL;

static void dpu_thread_set_affinity(thread_ctx_t *ctx)
{
    int i;
    int places = CORES/ctx->nthreads;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    
	for (i = 0; i < places; i++) {
		CPU_SET((ctx->idx*places)+i, &cpuset);
	}
    
    pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
}

static void dpu_coll_init_allreduce(thread_ctx_t *ctx, ucc_coll_req_h *request, size_t *count_p, dpu_put_sync_t *lsync)
{
    int ar_idx = ctx->buf_idx;
    assert(ctx->hc->pipeline.stage[ar_idx].get.state == DONE);
    assert(ctx->hc->pipeline.stage[ar_idx].ar.state  == IN_PROGRESS);
    assert(ctx->hc->pipeline.stage[ar_idx].put.state == FREE);

    ucc_datatype_t dtype = lsync->dtype;
    size_t dt_size = dpu_ucc_dt_size(dtype);
    size_t count = ctx->hc->pipeline.stage[ar_idx].get.count;
    size_t block = count / ctx->nthreads;
    size_t offset = block * ctx->idx * dt_size;
    
    void *src_buf = ctx->hc->pipeline.stage[ar_idx].get.buf;
    void *dst_buf = ctx->hc->pipeline.stage[ar_idx].put.buf;
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
            .buffer   = (char *)src_buf + offset,
            .count    = block,
            .datatype = dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = (char *)dst_buf + offset,
            .count    = block,
            .datatype = dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .reduce = {
            .predefined_op = lsync->op,
        },
    };

    UCC_CHECK(ucc_collective_init(&coll, request, ctx->comm.team));
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
}

void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
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
        sync[i].todo = 1;
    }
}

void dpu_wait_for_next_coll(thread_ctx_t *ctx)
{
    dpu_hc_wait(ctx->hc, ctx->coll_sync.coll_id);
    __sync_synchronize();
}

void dpu_mark_coll_done(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    ctx->coll_sync.count_serviced = lsync->count_total;
    dpu_hc_reply(ctx->hc, &ctx->coll_sync);
}

void dpu_comm_worker(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    dpu_put_sync_t *lsync = ctx->hc->mem_segs.sync.base;
    assert(ctx->idx == -1);
    CTX_LOG("Started comm thread\n");


    while (1) {
        ctx->coll_sync.coll_id++;
        ctx->coll_sync.count_serviced = 0;
        ctx->buf_idx = 0;

        dpu_wait_for_next_coll(ctx);
        dpu_signal_comp_threads(ctx, thread_main_sync);

        unsigned int    coll_id     = lsync->coll_id;
        ucc_coll_type_t coll_type   = lsync->coll_type;
        size_t          count_total = lsync->count_total;
        CTX_LOG(
            "Start coll id: %d, type: %d, count total: %lu\n",
            coll_id, coll_type, count_total);

        if (coll_type == UCC_COLL_TYPE_LAST) {
            /* Hang up */
            break;
        }

        dpu_pipeline_t *pipe = &ctx->hc->pipeline;
        while (pipe->count_put.done < count_total) {
            dpu_hc_issue_get(ctx->hc, lsync, ctx);
            dpu_hc_issue_allreduce(ctx->hc, lsync, ctx);
            dpu_hc_issue_put(ctx->hc, lsync, ctx);
            dpu_hc_progress(ctx->hc, lsync, ctx);
        }

        dpu_waitfor_comp_threads(ctx, thread_main_sync);
        dpu_mark_coll_done(ctx, lsync);
        CTX_LOG("End coll id: %d, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)ctx->coll_sync.count_serviced);
    }
}

void *dpu_worker(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    dpu_put_sync_t *lsync = ctx->hc->mem_segs.sync.base;
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
                UCC_CHECK(ucc_collective_post(request));
                while (UCC_OK != ucc_collective_test(request)) {
                    ucc_context_progress(ctx->comm.ctx);
                }
                UCC_CHECK(ucc_collective_finalize(request));
            }
            
            size_t dt_size = dpu_ucc_dt_size(lsync->dtype);
            size_t count = ctx->hc->pipeline.stage[ctx->buf_idx].get.count;
            size_t block = count / ctx->nthreads;
            size_t offset = block * ctx->idx;
            size_t final_idx = ctx->coll_sync.count_serviced + offset;
            unsigned long *src_buf = (unsigned long*)(ctx->hc->pipeline.stage[ctx->buf_idx].get.buf + offset * dt_size);
            unsigned long *dst_buf = (unsigned long*)(ctx->hc->pipeline.stage[ctx->buf_idx].put.buf + offset * dt_size);
            CTX_LOG("coll id %d DATA i %lu src %lu dst %lu\n", ctx->coll_sync.coll_id, final_idx, *src_buf, *dst_buf);

            ctx->buf_idx = (ctx->buf_idx + 1) % ctx->hc->pipeline.num_buffers;
            ctx->coll_sync.count_serviced += count_serviced;

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
    dpu_comm_worker((void*)&tctx_pool[i]);

    for(i = 0; i < nthreads; i++) {
        pthread_join(tctx_pool[i].id, NULL);
        dpu_ucc_free_team(&ucc_glob, &tctx_pool[i].comm);
    }

    dpu_ucc_finalize(&ucc_glob);
    return 0;
}

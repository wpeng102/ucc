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

typedef struct thread_ctx_s {
    pthread_t       id;
    int             idx;
    int             nthreads;
    dpu_ucc_comm_t  comm;
    dpu_hc_t        *hc;
    unsigned int    buf_idx;
    dpu_get_sync_t  coll_sync;
} thread_ctx_t;

/* thread accisble data - split reader/writer */
typedef struct thread_sync_s {
    volatile unsigned int todo;     /* first cache line */
    volatile unsigned int pad1[15]; /* pad to 64bytes */
    volatile unsigned int done;     /* second cache line */
    volatile unsigned int pad2[15]; /* pad to 64 bytes */
} thread_sync_t;

static thread_sync_t *thread_main_sync = NULL;
static thread_sync_t *thread_sub_sync = NULL;
dpu_put_sync_t tmp_sync;

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

static void dpu_coll_init_allreduce(thread_ctx_t *ctx, ucc_coll_req_h *request, size_t *count_p)
{
    size_t dt_size = dpu_ucc_dt_size(tmp_sync.dtype);
    size_t max_elems = ctx->hc->pipeline.buffer_size/dt_size;
    size_t count = DPU_MIN(max_elems, (tmp_sync.count_in - ctx->coll_sync.count_serviced));
    size_t block = count / ctx->nthreads;
    size_t offset = ctx->buf_idx * ctx->hc->pipeline.buffer_size + block * ctx->idx * dt_size;
    *count_p = count;
    
    DPU_LOG("count %lu, block %lu, offset %lu\n", count, block, offset);
    if (block == 0) {
        *request = NULL;
        return;
    }
    /*if(ctx->idx < (count % ctx->nthreads)) {
        offset += ctx->idx * dt_size;
        block++;
    } else {
        offset += (count % ctx->nthreads) * dt_size;
    }*/

    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLREDUCE,
        .mask      = UCC_COLL_ARGS_FIELD_PREDEFINED_REDUCTIONS,
        .src.info = {
            .buffer   = (char *)ctx->hc->mem_segs.put.base + offset,
            .count    = block,
            .datatype = tmp_sync.dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = (char *)ctx->hc->mem_segs.get.base + offset,
            .count    = block,
            .datatype = tmp_sync.dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .reduce = {
            .predefined_op = tmp_sync.op,
        },
    };

    UCC_CHECK(ucc_collective_init(&coll, request, ctx->comm.team));
}

static void dpu_coll_init_alltoall(thread_ctx_t *ctx, ucc_coll_req_h *request, size_t *count_p)
{
    *count_p = tmp_sync.count_total;
    /* Multithreading not supported */
    if(ctx->idx > 0) {
        *request = NULL;
        return;
    }
    
    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLTOALL,
        .src.info = {
            .buffer   = ctx->hc->mem_segs.put.base,
            .count    = tmp_sync.count_total,
            .datatype = tmp_sync.dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = ctx->hc->mem_segs.get.base,
            .count    = tmp_sync.count_total,
            .datatype = tmp_sync.dtype,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
    };

    UCC_CHECK(ucc_collective_init(&coll, request, ctx->comm.team));
}

static void dpu_wait_for_next_coll(thread_ctx_t *ctx)
{
    int i;
    ctx->coll_sync.coll_id++;
    ctx->coll_sync.count_serviced = 0;
    ctx->buf_idx = 0;

    if (ctx->idx == 0) {
        /* Data arrived, main thread will synchronize sub threads */
        dpu_hc_wait(ctx->hc, ctx->coll_sync.coll_id);
        __sync_synchronize();

        for (i = 0; i < ctx->nthreads; i++) {
            thread_main_sync[i].done = 0;
            thread_main_sync[i].todo = 1;
        }
    }
    /* busy wait */
    while (!thread_main_sync[ctx->idx].todo);
}

static void dpu_wait_for_next_data(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    int i;
    if (ctx->idx == 0) {
        dpu_hc_get_data(ctx->hc, lsync);
        /* main waits for count_in to be updated from host */
        //while(lsync->count_in <= ctx->coll_sync.count_serviced);
        memcpy(&tmp_sync, lsync, sizeof(dpu_put_sync_t));
        __sync_synchronize();

        /* release threads */
        for (i = 0; i < ctx->nthreads; i++) {
            thread_sub_sync[i].done = 0;
            thread_sub_sync[i].todo = 1;
        }
    }
    
    /* busy wait */
    while (!thread_sub_sync[ctx->idx].todo);
}

static void dpu_mark_work_done(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    int i;
    thread_sub_sync[ctx->idx].todo = 0;
    thread_sub_sync[ctx->idx].done = 1;

    if (ctx->idx == 0) {
        /* ensure all threads are done with previous data */
        for (i = 0; i < ctx->nthreads; i++) {
            while(!thread_sub_sync[i].done);
        }
        //dpu_hc_put_data(ctx->hc, lsync);
        //dpu_hc_reply(ctx->hc, &ctx->coll_sync);
    }
}

static void dpu_mark_coll_done(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    int i;
    thread_main_sync[ctx->idx].todo = 0;
    thread_main_sync[ctx->idx].done = 1;

    if (ctx->idx == 0) {
        /* ensure all threads are done with previous coll */
        for (i = 0; i < ctx->nthreads; i++) {
            while(!thread_main_sync[i].done);
        }
        dpu_hc_put_data(ctx->hc, lsync);
        dpu_hc_reply(ctx->hc, &ctx->coll_sync);
    }
}

void *dpu_worker(void *arg)
{
    // fprintf (stdout, "sleeping %d\n", getpid());
    // sleep(20);

    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    dpu_put_sync_t *lsync = ctx->hc->mem_segs.sync.base;
    ucc_coll_req_h request = NULL;
    size_t count_serviced;

    dpu_thread_set_affinity(ctx);

    while(1) {
        dpu_wait_for_next_coll(ctx);

        unsigned int coll_id      = lsync->coll_id;
        ucc_coll_type_t coll_type = lsync->coll_type;
        size_t count_total        = lsync->count_total;
        DPU_LOG("Start coll id: %d, type: %d, count total: %lu, count in: %lu\n",
                coll_id, coll_type, count_total, (size_t)lsync->count_in);
        
        if (coll_type == UCC_COLL_TYPE_LAST) {
            /* Hang up */
            break;
        }

        /* Process all data */
        do {
            dpu_wait_for_next_data(ctx, lsync);
            DPU_LOG("Got data, count in: %lu\n", lsync->count_in);

            if (coll_type == UCC_COLL_TYPE_ALLREDUCE) {
                dpu_coll_init_allreduce(ctx, &request, &count_serviced);
            } else if (coll_type == UCC_COLL_TYPE_ALLTOALL) {
                dpu_coll_init_alltoall(ctx, &request, &count_serviced);
            } else if (coll_type == UCC_COLL_TYPE_LAST) {
                DPU_LOG("Received hangup, exiting loop\n");
                break;
            } else {
                DPU_LOG("Unsupported coll type: %d\n", coll_type);
            }

            if (request != NULL) {
                UCC_CHECK(ucc_collective_post(request));
                while (UCC_OK != ucc_collective_test(request)) {
                    ucc_context_progress(ctx->comm.ctx);
                }
                UCC_CHECK(ucc_collective_finalize(request));
            }
            
            ctx->coll_sync.count_serviced += count_serviced;
            ctx->buf_idx = (ctx->buf_idx + 1) % ctx->hc->pipeline.num_buffers;

            DPU_LOG("Done data, count serviced: %lu\n", ctx->coll_sync.count_serviced);
            dpu_mark_work_done(ctx, lsync);

        } while (ctx->coll_sync.count_serviced < count_total);

        assert(count_total == ctx->coll_sync.count_serviced);
        DPU_LOG("End coll id: %d, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)ctx->coll_sync.count_serviced);
        dpu_mark_coll_done(ctx, lsync);
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
    printf("DPU daemon: Running with %d threads\n", nthreads);

    tctx_pool = calloc(nthreads, sizeof(*tctx_pool));
    UCC_CHECK(dpu_ucc_init(argc, argv, &ucc_glob));

    thread_main_sync = aligned_alloc(64, nthreads * sizeof(*thread_main_sync));
    memset(thread_main_sync, 0, nthreads * sizeof(*thread_main_sync));

    thread_sub_sync = aligned_alloc(64, nthreads * sizeof(*thread_sub_sync));
    memset(thread_sub_sync, 0, nthreads * sizeof(*thread_sub_sync));

    memset(&tmp_sync, 0, sizeof(tmp_sync));

    hc = &hc_b;

    UCC_CHECK(dpu_hc_init(hc));
    UCC_CHECK(dpu_hc_accept(hc));

    for(i = 0; i < nthreads; i++) {
        UCC_CHECK(dpu_ucc_alloc_team(&ucc_glob, &tctx_pool[i].comm));
        tctx_pool[i].idx = i;
        tctx_pool[i].nthreads = nthreads;
        tctx_pool[i].hc       = hc;
        tctx_pool[i].coll_sync.coll_id = 0;
        tctx_pool[i].coll_sync.count_serviced = 0;
        tctx_pool[i].buf_idx = 0;

        if (i < nthreads - 1) {
            pthread_create(&tctx_pool[i].id, NULL, dpu_worker,
                           (void*)&tctx_pool[i]);
        }
    }

    /* The final DPU worker is executed in this context */
    dpu_worker((void*)&tctx_pool[i-1]);

    for(i = 0; i < nthreads; i++) {
        if (i < nthreads - 1) {
            pthread_join(tctx_pool[i].id, NULL);
        }
        dpu_ucc_free_team(&ucc_glob, &tctx_pool[i].comm);
//         printf("Thread %d joined!\n", i);
    }

    dpu_ucc_finalize(&ucc_glob);
    return 0;
}

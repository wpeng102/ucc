/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "server_ucc.h"
#include "host_channel.h"
#include "dpu_log.h"
#include "ucc/api/ucc.h"

#define CORES 6
#define MAX_THREADS 128

#define THREAD_IDX_WORKER 0
#define THREAD_IDX_COMM   1

dpu_ucc_global_t ucc_glob;
dpu_hc_t         hc;
dpu_get_sync_t   coll_sync = {0};
dpu_put_sync_t   tmp_sync = {0};

thread_sync_t syncs[2] = {0};
thread_sync_t *thread_main_sync = &syncs[0];
thread_sync_t *thread_sub_sync  = &syncs[1];

pthread_mutex_t sync_lock;

uint64_t dpu_coll_counter[UCC_COLL_TYPE_LAST] = {0};

static void dpu_coll_print_summary(void)
{
    int print_summary = 0;
    char *s = getenv("UCC_TL_DPU_PRINT_SUMMARY");
    if (s) { print_summary = !!atoi(s); }
    if (!print_summary) return;

    printf("# Summary ");
    /* TODO: find a more robust way to iterate */
    for (ucc_coll_type_t coll=1; coll<UCC_COLL_TYPE_LAST; coll <<= 1) {
        uint64_t count = dpu_coll_counter[coll];
        if (count > 0) {
            printf(" %s %lu ", ucc_coll_type_str(coll), count);
        }
        dpu_coll_counter[coll] = 0; /* Reset Counter */
    }
    printf("\n");
}

/* TODO: export ucc_mc.h */
ucc_status_t ucc_mc_reduce(const void *src1, const void *src2, void *dst,
                           size_t count, ucc_datatype_t dtype,
                           ucc_reduction_op_t op, ucc_memory_type_t mem_type);

ucc_status_t ucc_mc_reduce_multi(void *src1, void *src2, void *dst, size_t n_vectors,
                    size_t count, size_t stride, ucc_datatype_t dtype,
                    ucc_reduction_op_t op, ucc_memory_type_t mem_type);

/* TODO: include ucc_coll_utils.h */
static inline size_t
ucc_coll_args_get_count(const ucc_coll_args_t *args, const ucc_count_t *counts,
                        ucc_rank_t idx)
{
    if ((args->mask & UCC_COLL_ARGS_FIELD_FLAGS) &&
        (args->flags & UCC_COLL_ARGS_FLAG_COUNT_64BIT)) {
        return ((uint64_t *)counts)[idx];
    }
    return ((uint32_t *)counts)[idx];
}

static inline size_t
ucc_coll_args_get_displacement(const ucc_coll_args_t *args,
                               const ucc_aint_t *displacements, ucc_rank_t idx)
{
    if ((args->mask & UCC_COLL_ARGS_FIELD_FLAGS) &&
        (args->flags & UCC_COLL_ARGS_FLAG_DISPLACEMENTS_64BIT)) {
        return ((uint64_t *)displacements)[idx];
    }
    return ((uint32_t *)displacements)[idx];
}

static inline size_t
ucc_coll_args_get_total_count(const ucc_coll_args_t *args,
                              const ucc_count_t *counts, ucc_rank_t size)
{
    size_t count = 0;
    ucc_rank_t i;
    // TODO switch to base args and cache total count there - can we do it ?
    if ((args->mask & UCC_COLL_ARGS_FIELD_FLAGS) &&
        (args->flags & UCC_COLL_ARGS_FLAG_COUNT_64BIT)) {
        for (i = 0; i < size; i++) {
            count += ((uint64_t *)counts)[i];
        }
    } else {
        for (i = 0; i < size; i++) {
            count += ((uint32_t *)counts)[i];
        }
    }

    return count;
}

ucc_ep_map_t ucc_ep_map_from_array(ucc_rank_t **array, ucc_rank_t size,
                                   ucc_rank_t full_size, int need_free);

static void dpu_thread_set_affinity(thread_ctx_t *ctx)
{
    int places = 8;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    if (ctx->idx == THREAD_IDX_WORKER) {
        for (int i = 0; i < places; i+=2) {
            CPU_SET(i, &cpuset);
        }
    } else {
        CPU_SET(7, &cpuset);
    }

    pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
}

static ucc_status_t dpu_coll_do_blocking_alltoall(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* Only do in comm thread */
    assert(ctx->idx == THREAD_IDX_COMM);

    ucs_status_t status;
    size_t team_rank, team_size;
    dpu_hc_t *hc = ctx->hc;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    UCC_CHECK(ucc_team_get_size(team, (uint32_t*)&team_size));
    UCC_CHECK(ucc_team_get_my_ep(team, (uint64_t*)&team_rank));

    size_t count_total   = lsync->count_total;
    size_t my_count      = count_total / team_size;
    ucc_datatype_t dtype = lsync->coll_args.src.info.datatype;
    size_t dt_size       = dpu_ucc_dt_size(dtype);

    CTX_LOG("Doing alltoall on team id %d team size %d count %lu\n", lsync->team_id, team_size, count_total);

    for(int i = 0; i < team_size; i++) {
        int src_rank = (team_rank + i) % team_size;
        size_t src_offset = team_rank * my_count * dt_size;
        size_t dst_offset = src_rank * my_count * dt_size;

        ucs_status_ptr_t ucp_req = NULL;
        size_t nbytes    = my_count * dt_size;
        void * src_addr  = hc->host_src_rkeys[src_rank].desc.buf_addr + src_offset;
        void * dst_addr  = lsync->dst_rkey.buf_addr + dst_offset;

        ucp_request_param_t get_param = {
            .op_attr_mask = UCP_OP_ATTR_FIELD_MEMH,
            .memh = lsync->dst_rkey.memh,
        };

        DPU_LOG("Issue Get from %d src %p offset %lu dst %p offset %lu count %lu bytes %lu\n",
                src_rank, src_addr, src_offset, dst_addr, dst_offset, my_count, nbytes);
        ucp_worker_fence(hc->ucp_worker);
        ucp_req = ucp_get_nbx(
            hc->dpu_eps[src_rank], dst_addr, nbytes, (uint64_t)src_addr,
            hc->host_src_rkeys[src_rank].rkey, &get_param);
        status = _dpu_request_wait(hc->ucp_worker, ucp_req);
        if (status != UCS_OK) {
            return UCC_ERR_NO_RESOURCE;
        }
    }

    return UCC_OK;
}

static ucc_status_t dpu_coll_do_blocking_alltoallv(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* Only do in comm thread */
    assert(ctx->idx == THREAD_IDX_COMM);

    ucs_status_t status;
    ucc_rank_t team_rank, team_size;
    dpu_hc_t *hc = ctx->hc;
    ucc_coll_args_t *args = &lsync->coll_args;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    UCC_CHECK(ucc_team_get_size(team, (uint32_t*)&team_size));
    UCC_CHECK(ucc_team_get_my_ep(team, (uint64_t*)&team_rank));

    CTX_LOG("Doing alltoallv on team id %d team size %d\n", lsync->team_id, team_size);

    for(int i = 0; i < team_size; i++) {
        int src_rank = (team_rank + i) % team_size;
        
        dpu_put_sync_t *src_lsync = &hc->world_lsyncs[src_rank];
        size_t src_count = ucc_coll_args_get_count(args, src_lsync->src_v.counts, team_rank);
        size_t src_displ = ucc_coll_args_get_displacement(args, src_lsync->src_v.displs, team_rank);

        size_t dst_count = ucc_coll_args_get_count(args, lsync->dst_v.counts, src_rank);
        size_t dst_displ = ucc_coll_args_get_displacement(args, lsync->dst_v.displs, src_rank);

        ucc_datatype_t sdt   = src_lsync->coll_args.src.info_v.datatype;
        ucc_datatype_t rdt   = lsync->coll_args.dst.info_v.datatype;
        size_t sdt_size      = dpu_ucc_dt_size(sdt);
        size_t rdt_size      = dpu_ucc_dt_size(rdt);

        CTX_LOG("src rank %d count %d displ %d dtsize %d dst rank %d count %d displ %d dtsize %d\n",
                src_rank,  src_count, src_displ, sdt_size,
                team_rank, dst_count, dst_displ, rdt_size);

        assert(src_count * sdt_size == dst_count * rdt_size);

        size_t src_offset = src_displ * sdt_size;
        size_t dst_offset = dst_displ * rdt_size;

        ucs_status_ptr_t ucp_req = NULL;
        size_t nbytes    = src_count * sdt_size;
        void * src_addr  = hc->host_src_rkeys[src_rank].desc.buf_addr + src_offset;
        void * dst_addr  = lsync->dst_rkey.buf_addr + dst_offset;

        ucp_request_param_t get_param = {
            .op_attr_mask = UCP_OP_ATTR_FIELD_MEMH,
            .memh = lsync->dst_rkey.memh,
        };

        DPU_LOG("Issue Get from %d src %p offset %lu dst %p offset %lu count %lu bytes %lu\n",
                src_rank, src_addr, src_offset, dst_addr, dst_offset, src_count, nbytes);
        ucp_worker_fence(hc->ucp_worker);
        ucp_req = ucp_get_nbx(
            hc->dpu_eps[src_rank], dst_addr, nbytes, (uint64_t)src_addr,
            hc->host_src_rkeys[src_rank].rkey, &get_param);
        status = _dpu_request_wait(hc->ucp_worker, ucp_req);
        if (status != UCS_OK) {
            return UCC_ERR_NO_RESOURCE;
        }
    }

    return UCC_OK;
}

/* Ensure host_rkey and alias_rkey can point to the same struct */
static ucs_status_t dpu_import_host_rkey(ucp_context_h ucp_context,
                                         ucp_worker_h  ucp_worker,
                                         host_rkey_t *host_rkey,
                                         host_rkey_t *alias_rkey)
{
    ucp_mem_map_params_t map_params = {0};
    ucs_status_t         status;
    ucp_rkey_h           h_rkey;
    void                *alias_rkey_buf;
    size_t               alias_rkey_buf_len;

    status = ucp_worker_rkey_unpack(ucp_worker, host_rkey->rkey_buf, &h_rkey);
    if (status != UCS_OK) {
        fprintf(stderr, "ucp_worker_rkey_unpack failed: %s",
                ucs_status_string(status));
        return status;
    }

    map_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                            UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                            UCP_MEM_MAP_PARAM_FIELD_RKEY;
    map_params.address = host_rkey->buf_addr;
    map_params.length  = host_rkey->buf_len;
    map_params.rkey    = h_rkey;

    status = ucp_mem_map(ucp_context, &map_params, &alias_rkey->memh);
    if (status != UCS_OK) {
        fprintf(stderr, "ucp_mem_map failed: %s", ucs_status_string(status));
        return status;
    }

    /* Pack alias rkey */
    status = ucp_rkey_pack(ucp_context, alias_rkey->memh, &alias_rkey_buf, &alias_rkey_buf_len);
    if (status != UCS_OK) {
        fprintf(stderr, "ucp_rkey_pack failed: %s", ucs_status_string(status));
        return status;
    }

    alias_rkey->buf_addr     = host_rkey->buf_addr;
    alias_rkey->buf_len      = host_rkey->buf_len;
    alias_rkey->rkey_buf_len = alias_rkey_buf_len;
    memcpy(&alias_rkey->rkey_buf, alias_rkey_buf, alias_rkey_buf_len);

    ucp_rkey_buffer_release(alias_rkey_buf);
    ucp_rkey_destroy(h_rkey);
    return UCS_OK;
}

static void dpu_coll_collect_host_rkeys(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* Only do in comm thread */
    assert(ctx->idx == THREAD_IDX_COMM);
    CTX_LOG("Collecting Host rkeys on team id %d\n", lsync->team_id);

    int i, ep_rank;
    ucs_status_t status;
    ucc_coll_req_h request;
    dpu_hc_t *hc = ctx->hc;
    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    ucc_rank_t team_size = 0;
    UCC_CHECK(ucc_team_get_size(team, &team_size));
    void *src_buf = lsync;
    void *dst_buf = hc->world_lsyncs;

    assert(lsync->src_rkey.rkey_buf && lsync->src_rkey.buf_addr && lsync->src_rkey.rkey_buf_len > 0 && lsync->src_rkey.buf_len > 0);
    assert(lsync->dst_rkey.rkey_buf && lsync->dst_rkey.buf_addr && lsync->dst_rkey.rkey_buf_len > 0 && lsync->dst_rkey.buf_len > 0);

    /* Create aliased rkey for host src and dst buffers */
    dpu_import_host_rkey(hc->ucp_ctx, hc->ucp_worker, &lsync->src_rkey, &lsync->src_rkey);
    dpu_import_host_rkey(hc->ucp_ctx, hc->ucp_worker, &lsync->dst_rkey, &lsync->dst_rkey);

    ucc_coll_args_t coll = {
        .coll_type = UCC_COLL_TYPE_ALLGATHER,
        .src.info = {
            .buffer   = src_buf,
            .count    = sizeof(dpu_put_sync_t),
            .datatype = UCC_DT_INT8,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
        .dst.info = {
            .buffer   = dst_buf,
            .count    = sizeof(dpu_put_sync_t) * team_size,
            .datatype = UCC_DT_INT8,
            .mem_type = UCC_MEMORY_TYPE_HOST,
        },
    };

    CTX_LOG("Issue Allgather from ranks %d src %p dst %p bytes %lu\n",
            team_size, src_buf, dst_buf, sizeof(dpu_put_sync_t));
    UCC_CHECK(ucc_collective_init(&coll, &request, team));
    UCC_CHECK(ucc_collective_post(request));
    while (UCC_OK != ucc_collective_test(request)) {
        ucc_context_progress(ctx->comm.ctx);
    }
    UCC_CHECK(ucc_collective_finalize(request));

    memset(hc->host_src_rkeys, 0, sizeof(alias_rkey_t) * hc->world_size);
    memset(hc->host_dst_rkeys, 0, sizeof(alias_rkey_t) * hc->world_size);

    for (i = 0; i < team_size; i++) {
        ep_rank  = dpu_get_world_rank(hc, i, lsync->team_id, ctx);
        memcpy(&hc->host_src_rkeys[ep_rank].desc, &hc->world_lsyncs[i].src_rkey, sizeof(host_rkey_t));
        memcpy(&hc->host_dst_rkeys[ep_rank].desc, &hc->world_lsyncs[i].dst_rkey, sizeof(host_rkey_t));

        status = ucp_ep_rkey_unpack(hc->dpu_eps[ep_rank], (void*)hc->host_src_rkeys[ep_rank].desc.rkey_buf, &hc->host_src_rkeys[ep_rank].rkey);
        assert(UCS_OK == status);

        status = ucp_ep_rkey_unpack(hc->dpu_eps[ep_rank], (void*)hc->host_dst_rkeys[ep_rank].desc.rkey_buf, &hc->host_dst_rkeys[ep_rank].rkey);
        assert(UCS_OK == status);
        
        CTX_LOG("Rank %d with EP Rank %d team_id %d src buf %p dst buf %p\n", 
                i, ep_rank, lsync->team_id, hc->host_src_rkeys[ep_rank].desc.buf_addr, hc->host_dst_rkeys[ep_rank].desc.buf_addr);
    }

    hc->rail = lsync->rail;
    hc->dpu_per_node_cnt = lsync->dpu_per_node_cnt;
    assert(hc->dpu_per_node_cnt > 0 && hc->rail >= 0 && hc->rail < hc->dpu_per_node_cnt);
}

void dpu_coll_do_barrier(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    ucs_status_t status;
    ucc_coll_req_h request;
    ucc_coll_args_t coll = {
        .mask = 0,
        .coll_type = UCC_COLL_TYPE_BARRIER,
    };

    ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
    CTX_LOG("Issue Synchronizing Barrier on team %d\n", lsync->team_id);
    assert(team != NULL);

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
        if (ctx->hc->host_src_rkeys[i].rkey != NULL)
            ucp_rkey_destroy(ctx->hc->host_src_rkeys[i].rkey);
        if (ctx->hc->host_dst_rkeys[i].rkey != NULL)
            ucp_rkey_destroy(ctx->hc->host_dst_rkeys[i].rkey);
    }
}

void dpu_waitfor_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    while (!sync->todo);
    assert(!sync->done);
}

void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    pthread_mutex_lock(&sync_lock);
    assert(sync->todo);
    assert(!sync->done);
    sync->todo = 0;
    sync->done = 1;
    pthread_mutex_unlock(&sync_lock);
}

void dpu_waitfor_comp_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    while (!sync->done);
}

void dpu_signal_comp_thread(thread_ctx_t *ctx, thread_sync_t *sync)
{
    pthread_mutex_lock(&sync_lock);
    sync->done = 0;
    sync->todo = 1;
    pthread_mutex_unlock(&sync_lock);
}

void dpu_wait_for_next_coll(thread_ctx_t *ctx)
{
    CTX_LOG("Waiting for host to initiate coll id: %u\n", ctx->coll_sync->coll_id);
    dpu_hc_wait(ctx->hc, ctx->coll_sync->coll_id);
    
    memcpy(&tmp_sync, (dpu_put_sync_t*)ctx->hc->mem_segs.sync.base, sizeof(tmp_sync));
    __sync_synchronize();
}

void dpu_mark_coll_done(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    assert(ctx->coll_sync->coll_id == lsync->coll_id);
    ctx->coll_sync->count_serviced = lsync->count_total;
    dpu_hc_reply(ctx->hc, ctx->coll_sync);
}

static ucc_status_t dpu_create_comm_team(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    /* read in the rank list in comm world */
    int i = 0, idx = 0, rail = 0;
    uint16_t team_id = lsync->team_id;
    ucc_rank_t full_size = ctx->hc->world_size;
    ucc_team_h new_team = NULL;
    ucc_team_params_t team_params = {0};
    uint16_t dpu_per_node_cnt = lsync->dpu_per_node_cnt;
    ucc_rank_t host_team_size = lsync->num_ranks;
    ucc_rank_t dpu_team_size = host_team_size * dpu_per_node_cnt;
    ucc_status_t status;
    
    CTX_LOG("creating new team with team_id %u coll_id %d\n",
            team_id, lsync->coll_id);

    ucc_rank_t *dpu_rank_list = malloc(sizeof(ucc_rank_t) * dpu_team_size);
    ucc_rank_t *host_rank_list = malloc(sizeof(ucc_rank_t) * host_team_size);

    for (i = 0; i < host_team_size; i++) {
        for (rail = 0; rail < dpu_per_node_cnt; rail++) {
            dpu_rank_list[idx++] = (lsync->rank_list[i] * dpu_per_node_cnt) + rail;
        }
    }

    memcpy(host_rank_list, lsync->rank_list, sizeof(ucc_rank_t) * host_team_size);

    CTX_LOG("got the rank list from host, new dpu team size: %d and host team size: %d\n",
            dpu_team_size, host_team_size);

    /* now we have the rank list in comm world available  */
    team_params.ep_range = UCC_COLLECTIVE_EP_RANGE_CONTIG;
    team_params.mask     = UCC_TEAM_PARAM_FIELD_EP |
                           UCC_TEAM_PARAM_FIELD_EP_RANGE |
                           UCC_TEAM_PARAM_FIELD_EP_MAP;

    /* find my new rank in the new team */
    for(i = 0; i < dpu_team_size; i++) {
        if (dpu_rank_list[i] == ctx->hc->world_rank) {
            break;
        }
    }
    team_params.ep = i; 
    team_params.ep_map = ucc_ep_map_from_array(&dpu_rank_list, dpu_team_size, full_size, 0);

    status = ucc_team_create_post(&ctx->comm.ctx, 1, &team_params, &new_team);
    if (UCC_OK != status) {
        fprintf(stderr, "ucc_team_create_post failed with %d\n", status);
        goto err;
    }

    do {
        status = ucc_team_create_test(new_team);
        ucc_context_progress(ctx->comm.ctx);
    } while (UCC_INPROGRESS == status);
        
    if (UCC_OK != status) {
        fprintf(stderr, "ucc_team_create_test failed with %d\n", status);
        goto err;
    }

    /* a new team has been created, insert it into the thread context */
    assert(new_team != NULL);
    ctx->comm.team_pool[team_id] = new_team; 
    ctx->comm.dpu_team_ctx_ranks[team_id] = dpu_rank_list;
    ctx->comm.host_team_ctx_ranks[team_id] = host_rank_list;
    CTX_LOG("created new team with team_id %u size %d\n",
            team_id, dpu_team_size);
    return UCC_OK;

err:
    free(dpu_rank_list);
    free(host_rank_list);
    return status;
}

static ucc_status_t dpu_destroy_comm_team(thread_ctx_t *ctx, dpu_put_sync_t *lsync)
{
    uint16_t team_id = lsync->team_id;
    ucc_team_h team = ctx->comm.team_pool[team_id]; 
    ucc_status_t status;

    CTX_LOG("destroying team with team_id %d coll_id %d\n",
            team_id, lsync->coll_id);

    assert(team != NULL);
    status = ucc_team_destroy(team);
    if (status < 0) {
        fprintf(stderr, "ucc_team_destroy failed with %d\n", status);
        return status;
    }

    ctx->comm.team_pool[team_id] = NULL; 
    if (ctx->comm.dpu_team_ctx_ranks[team_id] != NULL) {
        free(ctx->comm.dpu_team_ctx_ranks[team_id]);
        ctx->comm.dpu_team_ctx_ranks[team_id] = NULL;
    }
    if (ctx->comm.host_team_ctx_ranks[team_id] != NULL) {
        free(ctx->comm.host_team_ctx_ranks[team_id]);
        ctx->comm.host_team_ctx_ranks[team_id] = NULL;
    }

    CTX_LOG("destroyed team with team_id %d\n", team_id);
    return status;
}

void *dpu_comm_thread(void *arg)
{
    thread_ctx_t    *ctx = (thread_ctx_t *)arg;
    dpu_hc_t        *hc = ctx->hc;
    uint32_t        coll_id, dpu_team_size;
    size_t          dpu_team_rank;
    ucc_coll_type_t coll_type; 
    size_t          count_total; 
    uint16_t        team_id; 
    uint16_t        create_team;
    uint16_t        rail; 
    uint16_t        dpu_per_node_cnt;

    dpu_put_sync_t  *lsync = &tmp_sync; //comm_thread_ctx->hc->mem_segs.sync.base;
    ucc_status_t    status;

    assert(ctx->idx == THREAD_IDX_COMM);
    dpu_thread_set_affinity(ctx);
    CTX_LOG("Started comm thread\n");


    while (1) {
        ctx->coll_sync->coll_id++;
        ctx->coll_sync->count_serviced = 0;

        CTX_LOG("Waiting for coll id: %u from host\n", ctx->coll_sync->coll_id);
        dpu_wait_for_next_coll(ctx);

        coll_id     = lsync->coll_id;
        coll_type   = lsync->coll_args.coll_type;
        count_total = lsync->count_total;
        team_id     = lsync->team_id;
        create_team = lsync->create_new_team;
        rail        = lsync->rail;
        dpu_per_node_cnt = lsync->dpu_per_node_cnt;

        assert(0 <= team_id && team_id < DPU_TEAM_POOL_SIZE);
        dpu_coll_counter[coll_type]++;

        CTX_LOG(
            "Start coll id: %u, type: %d, count total: %lu on team: %u "
            "rail: %d, dpu count: %d, create: %d\n",
            coll_id, coll_type, count_total, team_id, rail, dpu_per_node_cnt, create_team);


        if (coll_type == UCC_COLL_TYPE_LAST) {
            if (create_team == 1) {

                dpu_create_comm_team(ctx, lsync);
                dpu_signal_comp_thread(ctx, thread_main_sync);
                dpu_waitfor_comp_thread(ctx, thread_main_sync);
                continue;

            } else if (team_id == UCC_WORLD_TEAM_ID) {

                /* World team free so Hang up */
                dpu_signal_comp_thread(ctx, thread_main_sync);
                /* Don't send a response back to Host */
                // dpu_mark_coll_done(ctx, lsync);
                // ucp_rkey_destroy(hc->src_rkey);
                // ucp_rkey_destroy(hc->dst_rkey);
                break;

            } else {

                /* releasing a subcomm's team that was already created
                 * on the dpu world */

                dpu_destroy_comm_team(ctx, lsync);
                dpu_signal_comp_thread(ctx, thread_main_sync);
                dpu_waitfor_comp_thread(ctx, thread_main_sync);
                continue;
            }
        }

        else if (coll_type == UCC_COLL_TYPE_ALLREDUCE) {
            dpu_coll_collect_host_rkeys(ctx, lsync);
            ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
            assert(team != NULL);
            UCC_CHECK(ucc_team_get_size(team, &dpu_team_size));
            UCC_CHECK(ucc_team_get_my_ep(team, &dpu_team_rank));
 
            ucc_datatype_t dtype = lsync->coll_args.src.info.datatype;
            size_t dt_size = dpu_ucc_dt_size(dtype);
            hc->pipeline.my_count  = lsync->count_total / dpu_team_size;
            hc->pipeline.my_offset = hc->pipeline.my_count * dt_size * dpu_team_rank;
            if (dpu_team_rank == dpu_team_size - 1) {
                hc->pipeline.my_count += lsync->count_total % dpu_team_size;
            }

            dpu_signal_comp_thread(ctx, thread_main_sync);
            while (hc->pipeline.count_serviced < hc->pipeline.my_count) {
                dpu_hc_progress_allreduce(ctx->hc, lsync, ctx);
            }
            dpu_hc_issue_hangup(ctx->hc, lsync, ctx);

            CTX_LOG("Waiting for worker threads to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_waitfor_comp_thread(ctx, thread_main_sync);

            CTX_LOG("Waiting for all ranks to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_coll_do_barrier(ctx, lsync);

            dpu_mark_coll_done(ctx, lsync);
            CTX_LOG("End coll id: %u, type: %d, count total: %lu, count serviced: %zu\n",
                    coll_id, coll_type, count_total, (size_t)ctx->coll_sync->count_serviced);

            dpu_coll_free_host_rkeys(ctx, lsync);
        }

        else if (coll_type == UCC_COLL_TYPE_ALLTOALL) {
            dpu_coll_collect_host_rkeys(ctx, lsync);
            
            dpu_coll_do_blocking_alltoall(ctx, lsync);

            CTX_LOG("Waiting for all ranks to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_coll_do_barrier(ctx, lsync);

            dpu_mark_coll_done(ctx, lsync);
            CTX_LOG("End coll id: %u, type: %d, count total: %lu, count serviced: %zu\n",
                    coll_id, coll_type, count_total, (size_t)ctx->coll_sync->count_serviced);

            dpu_coll_free_host_rkeys(ctx, lsync);
        }

        else if (coll_type == UCC_COLL_TYPE_ALLTOALLV) {
            dpu_coll_collect_host_rkeys(ctx, lsync);
            
            dpu_coll_do_blocking_alltoallv(ctx, lsync);

            CTX_LOG("Waiting for all ranks to complete coll id: %u, type: %d\n",
                    coll_id, coll_type);
            dpu_coll_do_barrier(ctx, lsync);

            dpu_mark_coll_done(ctx, lsync);
            CTX_LOG("End coll id: %u, type: %d, count total: %lu, count serviced: %zu\n",
                    coll_id, coll_type, count_total, (size_t)ctx->coll_sync->count_serviced);

            dpu_coll_free_host_rkeys(ctx, lsync);
        }
    }

    CTX_LOG("Communication thread is finalized \n");
}

void *dpu_worker_thread(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    dpu_put_sync_t *lsync = &tmp_sync; //ctx->hc->mem_segs.sync.base;
    ucc_coll_req_h request = NULL;
    size_t count_serviced;
    uint32_t dpu_team_size;

    assert(ctx->idx == THREAD_IDX_WORKER);
    dpu_thread_set_affinity(ctx);
    CTX_LOG("Started worker thread\n");

    while(1) {
        CTX_LOG("Waiting for coll id: %u from comm thread\n", ctx->coll_sync->coll_id);
        dpu_waitfor_comm_thread(ctx, thread_main_sync);

        uint32_t coll_id          = lsync->coll_id;
        size_t count_total        = lsync->count_total;
        ucc_coll_type_t coll_type = lsync->coll_args.coll_type;
        ucc_datatype_t dtype      = lsync->coll_args.src.info.datatype;
        ucc_reduction_op_t op     = lsync->coll_args.op;
        uint16_t create_team      = lsync->create_new_team;
        uint16_t team_id          = lsync->team_id;
        CTX_LOG("Start coll id: %d, type: %d, count total: %lu, team id: %u, create: %d\n",
                coll_id, coll_type, count_total, team_id, create_team);
        
        if (coll_type == UCC_COLL_TYPE_LAST) {
            if (create_team == 1) {

                dpu_create_comm_team(ctx, lsync);
                dpu_signal_comm_thread(ctx, thread_main_sync);
                continue;

            } else if (team_id == UCC_WORLD_TEAM_ID) {

                /* World team free so Hang up */
               // dpu_signal_comp_thread(ctx, thread_main_sync);
               // dpu_mark_coll_done(ctx, lsync);
                break;

            } else {

                /* releasing a subcomm's team that was already created
                 * on the dpu world */

                dpu_destroy_comm_team(ctx, lsync);
                dpu_signal_comm_thread(ctx, thread_main_sync);
                continue;
            }
        }

        int finished = 0;
        /* Process all data */
        do {
            CTX_LOG("Waiting for more data from comm thread\n");
            dpu_waitfor_comm_thread(ctx, thread_sub_sync);
            assert(UCC_COLL_TYPE_ALLREDUCE == coll_type);

            dpu_buf_t *accbuf = (dpu_buf_t*)thread_sub_sync->accbuf;
            dpu_buf_t *getbuf = (dpu_buf_t*)thread_sub_sync->getbuf;
            CTX_LOG("accbuf %p getbuf %p\n", accbuf, getbuf);
            if (accbuf == NULL && getbuf == NULL) {
                finished = 1;
                goto done;
            }
            assert(accbuf->state == REDUCING && accbuf->count > 0 && accbuf->ucp_req == NULL);
            assert(getbuf->state == REDUCING && getbuf->count > 0 && getbuf->ucp_req == NULL);

            size_t count = accbuf->count;
            // ucc_mc_reduce(accbuf->buf, getbuf->buf, accbuf->buf,
            //               count, dtype, op, UCC_MEMORY_TYPE_HOST);
            ucc_mc_reduce_multi(accbuf->buf, getbuf->buf, accbuf->buf,
                          1, count, 0, dtype, op, UCC_MEMORY_TYPE_HOST);
            CTX_LOG("Reduced %lu elements, serviced %lu out of %lu\n",
                    count, ctx->hc->pipeline.count_reduced, ctx->hc->pipeline.my_count);
        done:
            dpu_coll_do_barrier(ctx, lsync);
            dpu_signal_comm_thread(ctx, thread_sub_sync);

        } while (!finished);

        ucc_team_h team = ctx->comm.team_pool[lsync->team_id];
        assert(team != NULL);
        UCC_CHECK(ucc_team_get_size(team, &dpu_team_size));
        ctx->coll_sync->count_serviced = ctx->hc->pipeline.my_count * dpu_team_size;
        CTX_LOG("End coll id: %d, type: %d, count total: %lu, count serviced: %zu\n",
                coll_id, coll_type, count_total, (size_t)ctx->coll_sync->count_serviced);
        dpu_signal_comm_thread(ctx, thread_main_sync);
    }

    CTX_LOG("Worker thread is finalized \n");
    return NULL;
}

void _cleanup()
{
    dpu_hc_finalize(ucc_glob.hc);
    dpu_ucc_finalize(&ucc_glob);
}

void _sighandler(int signal)
{
    printf("Caught signal %d\n", signal);
}

int main(int argc, char **argv)
{
    char *s = NULL;
    int omp_threads = 6;
    s = getenv("UCC_MC_CPU_REDUCE_NUM_THREADS");
    if (s) { omp_threads = atoi(s); }
    printf("DPU daemon: Running with %d OpenMP threads\n", omp_threads);
    
    int window_size = 32;
    s = getenv("UCC_TL_DPU_BCAST_WINDOW");
    if (s) { window_size = atoi(s); }

    UCC_CHECK(dpu_ucc_init(argc, argv, &ucc_glob));
    UCC_CHECK(dpu_hc_init(&hc));
    hc.window_size = window_size;
    ucc_glob.hc = &hc;

    /* Try to clean up on Exit */
    atexit(_cleanup);
    signal(SIGINT, _sighandler);

    while (1) {
        UCC_CHECK(dpu_hc_accept_job(&hc));
        UCS_CHECK(dpu_hc_connect_localhost_ep(&hc));

        thread_ctx_t worker_ctx = {
            .idx = THREAD_IDX_WORKER,
            .hc = &hc,
            .coll_sync = &coll_sync,
        };

        thread_ctx_t comm_ctx = {
            .idx = THREAD_IDX_COMM,
            .hc = &hc,
            .coll_sync = &coll_sync,
        };

        UCC_CHECK(dpu_ucc_alloc_team(&ucc_glob, &worker_ctx.comm));
        UCC_CHECK(dpu_ucc_alloc_team(&ucc_glob, &comm_ctx.comm));
        dpu_hc_connect_remote_hosts(&hc, &comm_ctx.comm);
        dpu_hc_connect_remote_dpus(&hc, &comm_ctx.comm);
        UCS_CHECK(dpu_send_init_completion(&hc));
        
        pthread_create(&worker_ctx.id, NULL, dpu_worker_thread, &worker_ctx);
        pthread_create(&comm_ctx.id, NULL, dpu_comm_thread, &comm_ctx);

        
        pthread_join(worker_ctx.id, NULL);
        pthread_join(comm_ctx.id, NULL);

        dpu_ucc_free_team(&ucc_glob, &worker_ctx.comm);
        dpu_ucc_free_team(&ucc_glob, &comm_ctx.comm);
        
        dpu_hc_reset_job(&hc);
        dpu_coll_print_summary();

        memset(&coll_sync, 0, sizeof(coll_sync));
        memset(&tmp_sync,  0, sizeof(tmp_sync));
        memset(thread_main_sync, 0, sizeof(thread_sync_t));
        memset(thread_sub_sync,  0, sizeof(thread_sync_t));
    }

    return 0;
}

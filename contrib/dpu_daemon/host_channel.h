/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef HOST_CHANNEL_H
#define HOST_CHANNEL_H

// #define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>

#include "server_ucc.h"
#include <ucc/api/ucc.h>
#include <ucp/api/ucp.h>

#define MAX_NUM_RANKS       128
#define MAX_RKEY_LEN        1024
#define IP_STRING_LEN       50
#define PORT_STRING_LEN     8
#define SUCCESS             0
#define ERROR               1
#define DEFAULT_PORT        13337

#define DPU_MIN(a,b) (((a)<(b))?(a):(b))
#define DPU_MAX(a,b) (((a)>(b))?(a):(b))

#define UCC_WORLD_TEAM_ID 1

#ifdef NDEBUG
#define DPU_LOG(...)
#define CTX_LOG(...)
#else
#define DPU_LOG(_fmt, ...)                                  \
do {                                                        \
    fprintf(stderr, "%s:%d:%s(): " _fmt,                    \
            __FILE__, __LINE__, __func__, ##__VA_ARGS__);   \
    fflush(stderr);                                                 \
} while (0)

#define CTX_LOG(_fmt, ...)                                          \
do {                                                                \
    fprintf(stderr, "[%d] %s:%d:%s(): " _fmt,                       \
            ctx->idx, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    fflush(stderr);                                                 \
} while (0)
#endif

extern size_t dpu_ucc_dt_sizes[UCC_DT_USERDEFINED];

typedef struct host_rkey_t {
    char    src_rkey_buf[MAX_RKEY_LEN];
    char    dst_rkey_buf[MAX_RKEY_LEN];
    size_t  src_rkey_len;
    size_t  dst_rkey_len;
    void   *src_buf;
    void   *dst_buf;
} host_rkey_t;

typedef struct buf_info_v_t {
    ucc_count_t counts[MAX_NUM_RANKS];
    ucc_count_t displs[MAX_NUM_RANKS];
} buf_info_v_t;

/* sync struct type
 * use it for counter, dtype, ar op, length */
typedef struct dpu_put_sync_t {
    host_rkey_t         rkeys;
    uint16_t            team_id;
    uint16_t            rail;
    uint16_t            dpu_per_node_cnt;
    uint16_t            create_new_team;
    uint16_t            num_ranks;
    ucc_rank_t          host_team_rank;
    ucc_rank_t          rank_list[MAX_NUM_RANKS];
    ucc_coll_args_t     coll_args;
    buf_info_v_t        src_v;
    buf_info_v_t        dst_v;
    volatile uint32_t   count_total;
    volatile uint32_t   coll_id;
} dpu_put_sync_t;

typedef struct dpu_get_sync_t {
    uint32_t  count_serviced;
    uint32_t  coll_id;
} dpu_get_sync_t;

typedef struct dpu_rkey_t {
    void    *rkey_addr;
    size_t  rkey_addr_len;
} dpu_rkey_t;

typedef struct dpu_mem_t {
    void *base;
    ucp_mem_h memh;
    dpu_rkey_t rkey;
} dpu_mem_t;

typedef struct dpu_mem_segs_t {
    dpu_mem_t sync;
    dpu_mem_t in;
    dpu_mem_t out;
    dpu_mem_t out2;
} dpu_mem_segs_t;

typedef enum dpu_buf_state_t {
    FREE,
    SENDRECV,
    REDUCE,
    IDLE,
    HOST,
} dpu_buf_state_t;

typedef struct dpu_buf_t {
    void                       *buf;
    volatile ucs_status_ptr_t   req;
} dpu_buf_t;

typedef struct dpu_bufs_t {
    dpu_buf_t   acc;
    dpu_buf_t   recv[2];
    dpu_buf_state_t    state;
    uint64_t    data_size;
    size_t      dt_size;
    uint32_t    count;
    uint32_t    trip;
    uint16_t    sidx;
    uint16_t    ridx;
} dpu_bufs_t;

typedef struct dpu_buff_info_t {
    uint32_t    buffer_size;
    uint32_t    buffer_count;
    uint32_t    max_bufs;
    uint32_t    active;
    uint32_t    completed;
} dpu_buf_info_t;

typedef struct dpu_ring_t {
    ucs_status_ptr_t    sync_req;
    ucp_ep_h right_dpu_ep;
    ucp_ep_h left_dpu_ep;

    dpu_bufs_t *bufs;

    dpu_buf_info_t buf_info;
    uint64_t reduce_idx;
    uint64_t send_idx;
    uint64_t vec_byte_get_offset;
    uint64_t vec_byte_put_offset;
    volatile uint64_t count_serviced;
    uint64_t count_servicing;
    uint64_t total_count;
} dpu_ring_t;

// typedef struct dpu_pipeline_t {
//     size_t              buffer_size;
//     size_t              num_buffers;
//     ucs_status_ptr_t    sync_req;
    
//     dpu_stage_t         stages[2];
//     size_t              my_count;
//     size_t              my_offset;

//     volatile size_t     count_received;
//     volatile size_t     count_reduced;
//     volatile size_t     count_serviced;
// } dpu_pipeline_t;

typedef struct dpu_hc_t {
    /* TCP/IP stuff */
    char *hname;
    char *ip;
    int connfd, listenfd;
    uint16_t port;
    /* Local UCX stuff */
    ucp_context_h ucp_ctx;
    ucp_worker_h ucp_worker;
    ucp_worker_attr_t worker_attr;
    ucp_request_param_t req_param;
    union {
        dpu_mem_segs_t mem_segs;
        dpu_mem_t mem_segs_array[3];
    };

    /* Remote UCX stuff */
    ucp_ep_h localhost_ep;
    uint64_t sync_addr;
    ucp_rkey_h src_rkey;
    ucp_rkey_h dst_rkey;

    dpu_ring_t  ring;

    /* remote eps */
    int world_rank;
    int world_size;
    uint64_t team_rank;
    uint32_t team_size;
    // ucp_ep_h *host_eps;

    // host_rkey_t *host_rkeys;
    // ucp_rkey_h *host_src_rkeys;
    // ucp_rkey_h *host_dst_rkeys;

    host_rkey_t host_vec_rkeys;
    ucp_rkey_h host_src_vec_rkey;
    ucp_rkey_h host_dst_vec_rkey;

    /* Multi-rail support */
    int rail;
    int dpu_per_node_cnt;

    /* global visibility of collectives */
    // dpu_put_sync_t *world_lsyncs;
} dpu_hc_t;

int dpu_hc_init(dpu_hc_t *dpu_hc);
int dpu_hc_accept(dpu_hc_t *hc);
int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync);
int dpu_hc_wait(dpu_hc_t *hc, unsigned int coll_id);
int dpu_hc_finalize(dpu_hc_t *dpu_hc);


typedef struct thread_ctx_t {
    pthread_t       id;
    int             idx;
    dpu_ucc_comm_t  comm;
    dpu_hc_t        *hc;
    dpu_get_sync_t  *coll_sync;
} thread_ctx_t;

/* thread accisble data - split reader/writer */
typedef struct thread_sync_t {
    uint32_t pad[7]; //64 cache line size
    volatile uint32_t todo;
    uint32_t pad2[7];
    volatile uint32_t done;
} thread_sync_t;

extern thread_sync_t *thread_main_sync;
extern thread_sync_t *thread_sub_sync;

// ucs_status_t dpu_hc_issue_get(dpu_hc_t *hc, dpu_put_sync_t *sync, dpu_stage_t *stage, dpu_buf_t *getbuf, thread_ctx_t *ctx);
// ucs_status_t dpu_hc_issue_put(dpu_hc_t *hc, dpu_put_sync_t *sync, dpu_stage_t *stage, dpu_buf_t *accbuf, thread_ctx_t *ctx);
// ucs_status_t dpu_hc_issue_allreduce(dpu_hc_t *hc, thread_ctx_t *ctx, dpu_stage_t *stage, dpu_buf_t *accbuf, dpu_buf_t *getbuf);
ucs_status_t dpu_hc_ring_allreduce(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_hangup(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_send_init_completion(dpu_hc_t *hc);

size_t dpu_ucc_dt_size(ucc_datatype_t dt);

void dpu_waitfor_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_waitfor_comp_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comp_thread(thread_ctx_t *ctx, thread_sync_t *sync);

ucs_status_t _dpu_request_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t request);

    
#endif

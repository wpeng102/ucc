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

#define MAX_RKEY_LEN        1024
#define IP_STRING_LEN       50
#define PORT_STRING_LEN     8
#define SUCCESS             0
#define ERROR               1
#define DEFAULT_PORT        13337

#define EXCHANGE_LENGTH_TAG 1ull
#define EXCHANGE_RKEY_TAG 2ull
#define EXCHANGE_ADDR_TAG 3ull

#define DPU_MIN(a,b) (((a)<(b))?(a):(b))
#define DPU_MAX(a,b) (((a)>(b))?(a):(b))

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
    char    rank_list_rkey[MAX_RKEY_LEN];
    size_t  src_rkey_len;
    size_t  dst_rkey_len;
    size_t  rank_list_rkey_len;
    void   *src_buf;
    void   *dst_buf;
    void   *rank_list;
} host_rkey_t;

/* sync struct type
 * use it for counter, dtype, ar op, length */
typedef struct dpu_put_sync_t {
    host_rkey_t         rkeys;
    uint16_t            team_id;
    uint16_t            create_new_team;
    ucc_datatype_t      dtype;
    ucc_reduction_op_t  op;
    ucc_coll_type_t     coll_type;
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
} dpu_mem_segs_t;

typedef enum dpu_buf_phase_t {
    INIT,
    REDUCE,
    BCAST,
} dpu_buf_phase_t;

typedef enum dpu_buf_state_t {
    FREE,
    IN_PROGRESS,
    IDLE,
} dpu_buf_state_t;

typedef struct op_count_t {
    int issued_ops;
    int done_ops;
} op_count_t;

typedef struct elem_count_t {
    size_t issued_elems;
    size_t done_elems;
} elem_count_t;

typedef struct dpu_buf_t {
    volatile dpu_buf_phase_t    phase;
    volatile dpu_buf_state_t    state;
    void                       *buf;
    volatile ucs_status_ptr_t   ucp_req;
    volatile size_t             count;
    volatile op_count_t         get, red, put;
} dpu_buf_t;

typedef struct dpu_pipeline_t {
    size_t              buffer_size;
    size_t              num_buffers;
    ucs_status_ptr_t    sync_req;

    volatile int get_idx;
    volatile int acc_idx;
    volatile int put_idx;
    dpu_buf_t    getbuf[2];
    dpu_buf_t    accbuf[2];
    volatile elem_count_t get, red, put;
    volatile int src_rank;
    volatile int dst_rank;
    size_t       my_count;
    size_t       my_offset;
} dpu_pipeline_t;

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
    ucp_rkey_h sync_rkey;

    /* pipeline buffer */
    dpu_pipeline_t  pipeline;

    /* remote eps */
    int world_rank;
    int world_size;
    ucp_ep_h *host_eps;
    ucp_ep_h *dpu_eps;
    host_rkey_t *host_rkeys;
    ucp_rkey_h *host_src_rkeys;
    ucp_rkey_h *host_dst_rkeys;
} dpu_hc_t;

int dpu_hc_init(dpu_hc_t *dpu_hc);
int dpu_hc_accept(dpu_hc_t *hc);
int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync);
int dpu_hc_wait(dpu_hc_t *hc, unsigned int coll_id);
int dpu_hc_finalize(dpu_hc_t *dpu_hc);


typedef struct thread_ctx_t {
    pthread_t       id;
    int             idx;
    int             nthreads;
    dpu_ucc_comm_t  comm;
    dpu_hc_t        *hc;
    unsigned int    buf_idx;
    dpu_get_sync_t  coll_sync;
} thread_ctx_t;

/* thread accisble data - split reader/writer */
typedef struct thread_sync_t {
    volatile unsigned int todo;     /* first cache line */
    volatile unsigned int pad1[15]; /* pad to 64bytes */
    volatile unsigned int done;     /* second cache line */
    volatile unsigned int pad2[15]; /* pad to 64 bytes */
    volatile int acc_idx, get_idx;
} thread_sync_t;

extern thread_sync_t *thread_main_sync;
extern thread_sync_t *thread_sub_sync;

ucs_status_t dpu_hc_issue_get(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_put(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_allreduce(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_progress(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_hangup(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);

size_t dpu_ucc_dt_size(ucc_datatype_t dt);

void dpu_waitfor_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_waitfor_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync);

ucs_status_t _dpu_request_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t request);

    
#endif

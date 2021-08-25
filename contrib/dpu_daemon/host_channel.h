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

#define MAX_RKEY_LEN        256
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
} while (0)

#define CTX_LOG(_fmt, ...)                                          \
do {                                                                \
    fprintf(stderr, "[%d] %s:%d:%s(): " _fmt,                       \
            ctx->idx, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
} while (0)
#endif

extern size_t dpu_ucc_dt_sizes[UCC_DT_USERDEFINED];

typedef struct dpu_request_t {
    int complete;
} dpu_request_t;

typedef struct host_rkey_t {
    char    src_rkey_buf[MAX_RKEY_LEN];
    char    dst_rkey_buf[MAX_RKEY_LEN];
    size_t  src_rkey_len;
    size_t  dst_rkey_len;
    void   *src_buf;
    void   *dst_buf;
} host_rkey_t;

/* sync struct type
 * use it for counter, dtype, ar op, length */
typedef struct dpu_put_sync_t {
    host_rkey_t         rkeys;
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

typedef enum dpu_pipeline_stage_state_t {
    FREE,
    IN_PROGRESS,
    DONE,
} dpu_pipeline_stage_state_t;

typedef struct dpu_pipeline_stage_t {
    volatile dpu_pipeline_stage_state_t state;
    void                      *buf;
    dpu_request_t             *ucp_req;
    volatile size_t            count;
} dpu_pipeline_stage_t;

typedef struct dpu_stage_t {
    dpu_pipeline_stage_t get;
    dpu_pipeline_stage_t ar;
    dpu_pipeline_stage_t put;
} dpu_stage_t;

typedef struct inflight_t {
    volatile int get;
    volatile int put;
    volatile int ar;
} inflight_t;

typedef struct cur_idx_t {
    volatile int get;
    volatile int put;
    volatile int ar;
} cur_idx_t;

typedef struct count_t {
    volatile size_t issued;
    volatile size_t done;
} count_t;

typedef struct dpu_pipeline_t {
    dpu_stage_t         stage[2];
    inflight_t          inflight;
    cur_idx_t           idx;

    size_t              buffer_size;
    size_t              num_buffers;
    dpu_request_t      *sync_req;

    count_t count_get;
    count_t count_red;
    count_t count_put;
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
    ucp_ep_h host_ep;
    uint64_t sync_addr;
    ucp_rkey_h src_rkey;
    ucp_rkey_h dst_rkey;
    ucp_rkey_h sync_rkey;

    /* pipeline buffer */
    dpu_pipeline_t  pipeline;
} dpu_hc_t;

int dpu_hc_init(dpu_hc_t *dpu_hc);
int dpu_hc_accept(dpu_hc_t *hc);
int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync);
int dpu_hc_wait(dpu_hc_t *hc, unsigned int coll_id);


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
} thread_sync_t;

extern thread_sync_t *thread_main_sync;
extern thread_sync_t *thread_sub_sync;

ucs_status_t dpu_hc_issue_get(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_put(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_issue_allreduce(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);
ucs_status_t dpu_hc_progress(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx);

size_t dpu_ucc_dt_size(ucc_datatype_t dt);

void dpu_waitfor_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comm_thread(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_waitfor_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync);
void dpu_signal_comp_threads(thread_ctx_t *ctx, thread_sync_t *sync);

#endif
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
    volatile uint32_t   count_in;
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

typedef struct dpu_pipeline_t {
    size_t              buffer_size;
    void               *get_bufs[2];
    void               *put_bufs[2];
    dpu_request_t      *get_reqs[2];
    dpu_request_t      *put_reqs[2];
    dpu_request_t      *sync_req;
    size_t              get_idx;
    size_t              red_idx;
    size_t              put_idx;
    size_t              count_get;
    size_t              count_red;
    size_t              count_put;
    int                 gets_inflight;
    int                 puts_inflight;
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

int dpu_hc_issue_get(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync);
int dpu_hc_issue_put(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, dpu_get_sync_t *coll_sync);

size_t dpu_ucc_dt_size(ucc_datatype_t dt);

#endif
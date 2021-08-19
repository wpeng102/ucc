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

extern size_t dpu_ucc_dt_sizes[UCC_DT_USERDEFINED];

typedef struct dpu_req_s {
    int complete;
} dpu_req_t;

typedef struct host_rkey_s {
    char src_rkey[MAX_RKEY_LEN];
    char dst_rkey[MAX_RKEY_LEN];
    size_t src_rkey_len;
    size_t dst_rkey_len;
    void *src_buf;
    void *dst_buf;
} host_rkey_t;

/* sync struct type
 * use it for counter, dtype, ar op, length */
typedef struct dpu_put_sync_s {
    host_rkey_t         rkeys;
    ucc_datatype_t      dtype;
    ucc_reduction_op_t  op;
    ucc_coll_type_t     coll_type;
    volatile uint32_t   count_total;
    volatile uint32_t   count_in;
    volatile uint32_t   coll_id;
} dpu_put_sync_t;

typedef struct dpu_get_sync_s {
    uint32_t  count_serviced;
    uint32_t  coll_id;
} dpu_get_sync_t;

typedef struct dpu_rkey_s {
    void    *rkey_addr;
    size_t  rkey_addr_len;
} dpu_rkey_t;

typedef struct dpu_mem_s {
    void *base;
    ucp_mem_h memh;
    dpu_rkey_t rkey;
} dpu_mem_t;

typedef struct dpu_mem_segs_s {
    dpu_mem_t sync;
    dpu_mem_t in;
    dpu_mem_t out;
} dpu_mem_segs_t;

typedef struct dpu_pipeline_info_s {
    size_t buffer_size;
    size_t num_buffers;
} dpu_pipeline_info_t;

typedef struct dpu_pipeline_t {
    ucp_request_param_t      req_param;
    dpu_req_t                req;
    uint32_t                 count;
    uint32_t                 slot_idx;
    uint32_t                 in_flight;
} dpu_pipeline_t;

typedef struct dpu_hc_s {
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
    ucp_rkey_h sync_rkey;

    /* pipeline buffer */
    dpu_pipeline_info_t  pipeline;
    dpu_pipeline_t       rx;
    dpu_pipeline_t       tx;
} dpu_hc_t;

int dpu_hc_init(dpu_hc_t *dpu_hc);
int dpu_hc_accept(dpu_hc_t *hc);
int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync);
int dpu_hc_wait(dpu_hc_t *hc, unsigned int coll_id);

int dpu_hc_get_data(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync);
int dpu_hc_put_data(dpu_hc_t *dpu_hc, dpu_put_sync_t *sync, dpu_get_sync_t *coll_sync);

size_t dpu_ucc_dt_size(ucc_datatype_t dt);

#endif
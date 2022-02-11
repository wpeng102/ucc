/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCC_TL_DPU_H_
#define UCC_TL_DPU_H_

#include "components/tl/ucc_tl.h"
#include "components/tl/ucc_tl_log.h"
#include "utils/ucc_mpool.h"
#include <ucp/api/ucp.h>
#include <limits.h>

#ifndef UCC_TL_DPU_DEFAULT_SCORE
#define UCC_TL_DPU_DEFAULT_SCORE 30
#endif

#define UCC_TL_DPU_TC_POLL      10
#define UCC_TL_DPU_TASK_REQS    10

#define MAX_DPU_HOST_NAME 256
#define MAX_DPU_HCA_NAME  20
#define MAX_RKEY_LEN      1024
#define MAX_NUM_RANKS     128
#define MAX_DPU_COUNT     16 /* Max dpu per node */

typedef enum {
    UCC_TL_DPU_TASK_STATUS_INIT,
    UCC_TL_DPU_TASK_STATUS_POSTED,
    UCC_TL_DPU_TASK_STATUS_DONE,
    UCC_TL_DPU_TASK_STATUS_FINALIZED,
} ucc_tl_dpu_task_status_t;

typedef struct ucc_tl_dpu_iface {
    ucc_tl_iface_t super;
} ucc_tl_dpu_iface_t;
extern ucc_tl_dpu_iface_t ucc_tl_dpu;

typedef struct ucc_tl_dpu_lib_config {
    ucc_tl_lib_config_t super;
} ucc_tl_dpu_lib_config_t;

typedef struct ucc_tl_dpu_context_config {
    ucc_tl_context_config_t super;
    uint32_t                server_port;
    char                    *server_hname;
    char                    *host_dpu_list;
    size_t                  pipeline_buffer_size;
    size_t                  pipeline_num_buffers;
} ucc_tl_dpu_context_config_t;

typedef struct ucc_tl_dpu_lib {
    ucc_tl_lib_t            super;
    ucc_tl_dpu_lib_config_t cfg;
} ucc_tl_dpu_lib_t;
UCC_CLASS_DECLARE(ucc_tl_dpu_lib_t, const ucc_base_lib_params_t *,
                  const ucc_base_config_t *);

typedef struct ucc_tl_dpu_get_sync_t {
    volatile uint32_t       count_serviced;
    volatile uint32_t       coll_id;
} ucc_tl_dpu_get_sync_t;

typedef struct ucc_tl_dpu_connect {
    ucp_context_h               ucp_context;
    ucp_worker_h                ucp_worker;
    uint64_t                    rem_ctrl_seg;
    ucp_rkey_h                  rem_ctrl_seg_key;
    uint32_t                    coll_id_issued;
    uint32_t                    coll_id_completed;
    ucc_tl_dpu_get_sync_t       get_sync; 
    ucp_ep_h                    ucp_ep;
    volatile size_t             inflight;
} ucc_tl_dpu_connect_t;

typedef struct ucc_tl_dpu_context {
    ucc_tl_context_t            super;
    ucc_mpool_t                 req_mp;
    ucc_tl_dpu_context_config_t cfg;   
    int                         dpu_per_node_cnt;
    ucc_tl_dpu_connect_t        dpu_ctx_list[MAX_DPU_COUNT];
} ucc_tl_dpu_context_t;

UCC_CLASS_DECLARE(ucc_tl_dpu_context_t, const ucc_base_context_params_t *,
                  const ucc_base_config_t *);

typedef struct ucc_tl_dpu_rkeys_t {
    char src_rkey[MAX_RKEY_LEN];
    char dst_rkey[MAX_RKEY_LEN];
    size_t src_rkey_len;
    size_t dst_rkey_len;
    void *src_buf;
    void *dst_buf;
} ucc_tl_dpu_put_rkeys_t;

typedef struct buf_info_v_t {
    ucc_count_t counts[MAX_NUM_RANKS];
    ucc_count_t displs[MAX_NUM_RANKS];
} buf_info_v_t;

typedef struct ucc_tl_dpu_put_sync_t {
    ucc_tl_dpu_put_rkeys_t   rkeys;
    uint16_t                 team_id;
    uint16_t                 rail;
    uint16_t                 dpu_per_node_cnt;
    uint16_t                 create_new_team;
    uint16_t                 num_ranks;
    ucc_rank_t               rank_list[MAX_NUM_RANKS];
    ucc_coll_args_t          coll_args;
    buf_info_v_t             src_v;
    buf_info_v_t             dst_v;
    uint32_t                 count_total;
    uint32_t                 coll_id;
} ucc_tl_dpu_put_sync_t;

typedef struct ucc_tl_dpu_rkey_t {
    ucp_mem_h memh;
    void     *rkey_buf;
    size_t    rkey_buf_size;
} ucc_tl_dpu_rkey_t;

typedef struct ucc_tl_dpu_sync {
    uint32_t              coll_id_issued;
    uint32_t              coll_id_completed;
    ucc_status_t          status;
} ucc_tl_dpu_sync_t;

typedef struct ucc_tl_dpu_team {
    ucc_tl_team_t         super;
    ucc_status_t          status;
    ucc_rank_t            size;
    ucc_rank_t            rank;
    int                   dpu_per_node_cnt;
    ucc_tl_dpu_sync_t     dpu_sync_list[MAX_DPU_COUNT];
} ucc_tl_dpu_team_t;
UCC_CLASS_DECLARE(ucc_tl_dpu_team_t, ucc_base_context_t *,
                  const ucc_base_team_params_t *);

typedef struct ucc_tl_dpu_task_req_t {
    ucs_status_ptr_t send_req;
    ucs_status_ptr_t recv_req;
} ucc_tl_dpu_task_req_t;

typedef struct ucc_tl_dpu_sub_task {
    ucc_tl_dpu_put_sync_t    put_sync;
    ucc_tl_dpu_get_sync_t    get_sync;
    ucc_tl_dpu_task_req_t    task_reqs;
    ucc_tl_dpu_rkey_t        src_rkey;
    ucc_tl_dpu_rkey_t        dst_rkey;
    volatile ucc_tl_dpu_task_status_t status;
} ucc_tl_dpu_sub_task_t;

typedef struct ucc_tl_dpu_task {
    ucc_coll_task_t          super;
    ucc_coll_args_t          args;
    ucc_tl_dpu_team_t        *team;
    volatile ucc_tl_dpu_task_status_t status;
    int                      dpu_per_node_cnt;
    ucc_tl_dpu_sub_task_t    dpu_task_list[MAX_DPU_COUNT];
} ucc_tl_dpu_task_t;

typedef struct ucc_tl_dpu_config {
    ucc_tl_lib_config_t super;
} ucc_tl_dpu_config_t;

typedef struct ucc_tl_dpu {
    ucc_tl_lib_t        super;
    ucc_tl_dpu_config_t config;
} ucc_tl_dpu_t;

#define UCC_TL_DPU_SUPPORTED_COLLS \
    (UCC_COLL_TYPE_ALLREDUCE | UCC_COLL_TYPE_ALLTOALL | UCC_COLL_TYPE_ALLTOALLV)

#define UCC_TL_DPU_TEAM_LIB(_team)                                          \
    (ucc_derived_of((_team)->super.super.context->lib, ucc_tl_dpu_lib_t))

#define UCC_TL_DPU_TEAM_CTX(_team)                                          \
    (ucc_derived_of((_team)->super.super.context, ucc_tl_dpu_context_t))

#define UCC_TL_DPU_TEAM_CORE_CTX(_team)                                     \
    ((_team)->super.super.context->ucc_context)

ucc_status_t ucc_tl_dpu_req_test(ucs_status_ptr_t *req_p, ucp_worker_h worker);
ucc_status_t ucc_tl_dpu_req_check(ucc_tl_dpu_team_t *team, ucs_status_ptr_t req);
ucc_status_t ucc_tl_dpu_req_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t req);
ucs_status_t ucc_tl_dpu_register_buf( ucp_context_h ucp_ctx, void *base, size_t size, ucc_tl_dpu_rkey_t *rkey);
ucc_status_t ucc_tl_dpu_deregister_buf( ucp_context_h ucp_ctx, ucc_tl_dpu_rkey_t *rkey);

#endif

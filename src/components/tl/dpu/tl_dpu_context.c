/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "tl_dpu.h"
#include "tl_dpu_coll.h"
#include "utils/arch/cpu.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <assert.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

static ucc_mpool_ops_t ucc_tl_dpu_req_mpool_ops = {
    .chunk_alloc   = ucc_mpool_hugetlb_malloc,
    .chunk_release = ucc_mpool_hugetlb_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL
};

static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    ucc_error("error handling callback was invoked with status %d (%s)\n",
                    status, ucs_status_string(status));
}

static ucs_status_t
ucc_tl_dpu_rcache_mem_reg_cb(void *context, ucc_rcache_t *rcache,
                               void *arg, ucc_rcache_region_t *rregion,
                               uint16_t flags)
{
    ucc_tl_dpu_connect_t       *connect = (ucc_tl_dpu_connect_t*)context;
    ucc_tl_dpu_context_t       *ctx     = connect->dpu_context;
    ucc_tl_dpu_rcache_region_t *region;
    void                       *address;
    size_t                      length;
    ucs_status_t                ret;

    address = (void*)rregion->super.start;
    length  = (size_t)(rregion->super.end - rregion->super.start);
    region  = ucc_derived_of(rregion, ucc_tl_dpu_rcache_region_t);

    ret = dpu_coll_reg_mr(connect->ucp_context,
                          address, length, &region->reg);

    if (ret != UCS_OK) {
        tl_error(ctx->super.super.lib, "dpu_coll_reg_mr failed(%d) addr:%p len:%zd",
                 ret, address, length);
        return UCS_ERR_INVALID_PARAM;
    } else {
        tl_debug(ctx->super.super.lib, "dpu_coll_reg_mr_cb region:%p addr:%p len:%zd",
                &region->reg, region->reg.reg_addr, region->reg.reg_len);
        return UCS_OK;
    }
}

static void ucc_tl_dpu_rcache_mem_dereg_cb(void *context, ucc_rcache_t *rcache,
                                             ucc_rcache_region_t *rregion)
{
    ucc_tl_dpu_connect_t       *connect = (ucc_tl_dpu_connect_t*)context;
    ucc_tl_dpu_context_t       *ctx     = connect->dpu_context;
    ucc_tl_dpu_rcache_region_t *region  = ucc_derived_of(rregion,
                                                ucc_tl_dpu_rcache_region_t);
    ucs_status_t                ret;

    ret = dpu_coll_dereg_mr(connect->ucp_context, &region->reg);
    if (ret != UCS_OK) {
        tl_error(ctx->super.super.lib, "dpu_coll_dereg_mr failed(%d)", ret);
    } else {
        tl_debug(ctx->super.super.lib, "dpu_coll_dereg_mr_cb region:%p addr:%p len:%zd",
                &region->reg, region->reg.reg_addr, region->reg.reg_len);
    }
}

static void
ucc_tl_dpu_rcache_dump_region_cb(void *context, ucs_rcache_t *rcache,
                                   ucs_rcache_region_t *rregion, char *buf,
                                   size_t max)
{
    ucc_tl_dpu_rcache_region_t *region = ucc_derived_of(rregion,
                                           ucc_tl_dpu_rcache_region_t);

    snprintf(buf, max, "addr %p len %zu", region->reg.reg_addr, region->reg.reg_len);
}

static ucc_rcache_ops_t ucc_tl_dpu_rcache_ops = {
    .mem_reg     = ucc_tl_dpu_rcache_mem_reg_cb,
    .mem_dereg   = ucc_tl_dpu_rcache_mem_dereg_cb,
    .dump_region = ucc_tl_dpu_rcache_dump_region_cb
};

static int _server_connect(ucc_tl_dpu_context_t *ctx, char *hname, uint16_t port)
{
    int sock = -1, n;
    struct addrinfo *res, *t;
    struct addrinfo hints = { 0 };
    char service[64];

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    sprintf(service, "%d", port);
    n = getaddrinfo(hname, service, &hints, &res);

    if (n < 0) {
        tl_error(ctx->super.super.lib, "%s:%d: getaddrinfo(): %s for %s:%s\n", __FILE__,__LINE__, gai_strerror(n), hname, service);
        return -1;
    }

    for (t = res; t; t = t->ai_next) {
        sock = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sock >= 0) {
            if (0 > connect(sock, t->ai_addr, t->ai_addrlen)) {
                tl_error(ctx->super.super.lib, "Connect failed with errno %d (%s)\n", errno, strerror(errno));
                close(sock);
                sock = -1;
            } else {
                break;
            }
        }
    }

    freeaddrinfo(res);
    return sock;
}

static int _server_spawn(ucc_tl_dpu_context_t *ctx, char *hname, int sockfd_master)
{
    int sock = -1;
    uint32_t port;
    int ret;
    struct addrinfo *res, *t;
    struct addrinfo hints = { 0 };
    char service[64];

    /* FIXME: does not work for non-MPI */
    uint32_t local_rank = atoi(getenv("OMPI_COMM_WORLD_LOCAL_RANK"));
    ret = send(sockfd_master, &local_rank, sizeof(uint32_t), 0);
    if (ret < 0) {
        tl_error(ctx->super.super.lib, "send local rank failed");
        goto err;
    }

    ret = recv(sockfd_master, &port, sizeof(uint32_t), MSG_WAITALL);
    if (ret < 0) {
        tl_error(ctx->super.super.lib, "recv port info failed");
        goto err;
    }
    tl_info(ctx->super.super.lib, "Recvd spawn response, local rank %d port %d\n", local_rank, port);

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    sprintf(service, "%d", port);

    ret = getaddrinfo(hname, service, &hints, &res);
    if (ret < 0) {
        tl_error(ctx->super.super.lib, "%s:%d: getaddrinfo(): %s for %s:%s\n", __FILE__,__LINE__, gai_strerror(ret), hname, service);
        goto err;
    }

    for (t = res; t; t = t->ai_next) {
        sock = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sock < 0) {
            tl_error(ctx->super.super.lib, "Socket failed with errno %d (%s)\n", errno, strerror(errno));
            goto err_sock;
        }

        /* TODO: Add timeout or max retries */
        do {
            usleep(1000);
            ret = connect(sock, t->ai_addr, t->ai_addrlen);
        } while (ret < 0 && errno == ECONNREFUSED);

        if (ret < 0) {
            tl_error(ctx->super.super.lib, "Connect failed with errno %d (%s)\n", errno, strerror(errno));
            goto err_sock;
        }
    }

    freeaddrinfo(res);
err:
    close(sockfd_master);
    return sock;
err_sock:
    close(sock);
    sock = -1;
    goto err;
}

UCC_CLASS_INIT_FUNC(ucc_tl_dpu_context_t,
                    const ucc_base_context_params_t *params,
                    const ucc_base_config_t *config)
{ 
    /* TODO: Need handshake with daemon for detection */
    ucc_tl_dpu_context_config_t *tl_dpu_config =
        ucc_derived_of(config, ucc_tl_dpu_context_config_t);

    ucc_status_t        ucc_status = UCC_OK;
    ucp_worker_params_t worker_params;
    ucp_worker_attr_t   worker_attr;
    ucp_params_t        ucp_params;
    ucp_ep_params_t     ep_params;
    ucp_ep_h            ucp_ep;
    ucp_context_h       ucp_context;
    ucp_worker_h        ucp_worker;
    int                 sockfd_master;
    int                 sockfd;

    int i, ret;
    int rail = 0;
    int hca = 0;
    int dpu_count = 0;
    int last_dpu_found = 0;

    /* Identify DPU */
    char hname[MAX_DPU_HOST_NAME];
    void *rem_worker_addr;
    size_t rem_worker_addr_size; 
    char dpu_hnames[MAX_DPU_COUNT][MAX_DPU_HOST_NAME];
    char dpu_hcanames[MAX_DPU_COUNT][MAX_DPU_HCA_NAME];
    char dpu_tmp[MAX_DPU_HOST_NAME];

    UCC_CLASS_CALL_SUPER_INIT(ucc_tl_context_t, &tl_dpu_config->super,
                              params->context);
    memcpy(&self->cfg, tl_dpu_config, sizeof(*tl_dpu_config));

    /* Find  DPU based on the host-dpu list */
    gethostname(hname, sizeof(hname) - 1);

    char *h = calloc(1, 256), *dpu;
    FILE *fp = NULL;

    if (strcmp(self->cfg.host_dpu_list,"") != 0) {

        fp = fopen(self->cfg.host_dpu_list, "r");
        if (fp == NULL) {
            tl_error(self->super.super.lib,
                "Unable to open host_dpu_list \"%s\", disabling dpu team\n", self->cfg.host_dpu_list);
            ucc_status = UCC_ERR_NO_MESSAGE;
        }
        else {
            rail = 0, hca = 0;
            while (fscanf(fp,"%s", h) != EOF) {
                if (strcmp(h, hname) == 0) {
                    for (i = 0; i < 2 * MAX_DPU_COUNT; i++) {
                        memset(dpu_tmp, 0, MAX_DPU_HOST_NAME);
                        fscanf(fp, "%s", dpu_tmp);

                        if(strchr(dpu_tmp, ',') != NULL)
                        {
                            last_dpu_found = 1;
                            /* remove the tail (,) */
                            memmove(&dpu_tmp[strlen(dpu_tmp) - 1], &dpu_tmp[strlen(dpu_tmp)], 1);
                        }

                        if(strstr(dpu_tmp, "mlx5_") != NULL) {
                            memcpy(dpu_hcanames[hca], dpu_tmp, MAX_DPU_HCA_NAME);
                            hca++;
                            if(last_dpu_found) { 
                                break;
                            }
                            continue;
                        } 

                        memcpy(dpu_hnames[rail], dpu_tmp, MAX_DPU_HOST_NAME);
                        rail++;                        

                        tl_info(self->super.super.lib, "DPU <%s> found!\n",
                                dpu_tmp);

                        if(last_dpu_found) { 
                            break;
                        }
                    }
                }
                memset(h, 0, MAX_DPU_HOST_NAME);
            }
            if (rail != hca) {
                fprintf(stderr, "host_to_dpu.list file is not formatted correctly");
                goto err;
            }
            dpu_count = rail;
        }
        if (!dpu_count) {
            ucc_status = UCC_ERR_NO_MESSAGE;
        }
    }
    else {
        tl_error(self->super.super.lib,
            "DPU_ENABLE set, but HOST_LIST not specified. Disabling DPU team!\n");
        ucc_status = UCC_ERR_NO_MESSAGE;
    }
    free(h);

    if (UCC_OK != ucc_status) {
        goto err;
    }


    /* Setting the params for all the DPUs */
    memset(&ucp_params, 0, sizeof(ucp_params));
    ucp_params.field_mask       = UCP_PARAM_FIELD_FEATURES;
    ucp_params.features         = UCP_FEATURE_TAG                        |
                                  UCP_FEATURE_RMA;

    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask    = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode   = UCS_THREAD_MODE_MULTI;

    worker_attr.field_mask      = UCP_WORKER_ATTR_FIELD_ADDRESS          |
                                  UCP_WORKER_ATTR_FIELD_ADDRESS_FLAGS;
    worker_attr.address_flags   = UCP_WORKER_ADDRESS_FLAG_NET_ONLY;

    ep_params.field_mask        = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS      |
                                  UCP_EP_PARAM_FIELD_ERR_HANDLER         |
                                  UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode          = UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb    = err_cb;

    /* Start connecting to all the DPUs */
    for (rail = 0; rail < dpu_count; rail++) {
        dpu = *(dpu_hnames + rail);

        tl_info(self->super.super.lib, "Connecting to %s with hca id %s", dpu, dpu_hcanames[rail]);

        sockfd_master = _server_connect(self, dpu, tl_dpu_config->server_port);
        if (sockfd_master < 0) {
            tl_error(self->super.super.lib,
                "failed connecting to DPU master at %s:%d\n", dpu, tl_dpu_config->server_port);
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }

        sockfd = _server_spawn(self, dpu, sockfd_master);
        if (sockfd < 0) {
            tl_error(self->super.super.lib,
                "failed to spawn DPU server at %s\n", dpu);
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }

        memset(&ucp_context, 0, sizeof(ucp_context_h));
        ucp_config_t *ucp_config;
        ucp_config_read(NULL, NULL, &ucp_config);
        ucp_config_modify(ucp_config, "NET_DEVICES", dpu_hcanames[rail]);
        ucc_status = ucs_status_to_ucc_status(
                        ucp_init(&ucp_params, ucp_config, &ucp_context));
        if (ucc_status != UCC_OK) {
            tl_error(self->super.super.lib,
                "failed ucp_init(%s)\n", ucc_status_string(ucc_status));
            goto err;
        }

        memset(&ucp_worker, 0, sizeof(ucp_worker_h));
        ucc_status = ucs_status_to_ucc_status(
                        ucp_worker_create(ucp_context, &worker_params, &ucp_worker));
        if (ucc_status != UCC_OK) {
            tl_error(self->super.super.lib,
                "failed ucp_worker_create (%s)\n", ucc_status_string(ucc_status));
            goto err_cleanup_context;
        }

        ucp_worker_query(ucp_worker, &worker_attr);

        ret = send(sockfd, &worker_attr.address_length,
                sizeof(&worker_attr.address_length), 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send length failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        ret = send(sockfd, worker_attr.address, worker_attr.address_length, 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send address failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        ret = send(sockfd, &self->cfg.pipeline_buffer_size, sizeof(size_t), 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send pipeline size failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        ret = send(sockfd, &self->cfg.pipeline_num_buffers, sizeof(size_t), 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send pipeline num buffers failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        ret = recv(sockfd, &rem_worker_addr_size, sizeof(rem_worker_addr_size), MSG_WAITALL);
        if (ret < 0) {
            tl_error(self->super.super.lib, "recv address length failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        rem_worker_addr = ucc_malloc(rem_worker_addr_size, "rem_worker_addr");
        ep_params.address = rem_worker_addr;
        if (NULL == rem_worker_addr) {
            tl_error(self->super.super.lib, "failed to allocate rem_worker_addr");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        ret = recv(sockfd, rem_worker_addr, rem_worker_addr_size, MSG_WAITALL);
        if (ret < 0) {
            tl_error(self->super.super.lib, "recv address failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }
        
        uint32_t global_rank = UCC_TL_CTX_OOB(self).oob_ep;
        ret = send(sockfd, &global_rank, sizeof(uint32_t), 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send global rank failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }

        uint32_t global_size = UCC_TL_CTX_OOB(self).n_oob_eps;
        ret = send(sockfd, &global_size, sizeof(uint32_t), 0);
        if (ret < 0) {
            tl_error(self->super.super.lib, "send global size failed");
            ucc_status = UCC_ERR_NO_MESSAGE;
            goto err;
        }

        memset(&ucp_ep, 0, sizeof(ucp_ep_h));
        ucc_status = ucs_status_to_ucc_status(
                        ucp_ep_create(ucp_worker, &ep_params, &ucp_ep));
        free(worker_attr.address);
        ucc_free(rem_worker_addr);
        close(sockfd);
        if (ucc_status != UCC_OK) {
            tl_error(self->super.super.lib, "failed to connect to %s (%s)\n",
                           dpu, ucc_status_string(ucc_status));
            goto err_cleanup_worker;
        }

        ucc_tl_dpu_connect_t *dpu_connect      = &self->dpu_ctx_list[rail];
        dpu_connect->dpu_context               = self;
        dpu_connect->ucp_context               = ucp_context;
        dpu_connect->ucp_worker                = ucp_worker;
        dpu_connect->ucp_ep                    = ucp_ep;
        dpu_connect->inflight                  = 0;
        dpu_connect->coll_id_issued            = 0;
        dpu_connect->coll_id_completed         = 0;
        dpu_connect->get_sync.count_serviced   = 0;
        dpu_connect->get_sync.coll_id          = 0;
        dpu_connect->rcache                    = NULL;

        if (self->cfg.use_rcache) {
            ucc_rcache_params_t rcache_params = {
                .alignment          = 64,
                .ucm_event_priority = 1000,
                .max_regions        = ULONG_MAX,
                .max_size           = SIZE_MAX,
                .region_struct_size = sizeof(ucc_tl_dpu_rcache_region_t),
                .max_alignment      = getpagesize(),
                .ucm_events         = UCM_EVENT_VM_UNMAPPED | UCM_EVENT_MEM_TYPE_FREE,
                .context            = dpu_connect,
                .ops                = &ucc_tl_dpu_rcache_ops,
                .flags              = 0,
            };

            ucc_status = ucc_rcache_create(&rcache_params, "DPU", &dpu_connect->rcache);
            if (ucc_status != UCC_OK) {
                tl_error(self->super.super.lib, "failed to create rcache (%s)",
                         ucc_status_string(ucc_status));
                ucc_status = UCC_ERR_NO_RESOURCE;
                goto err_cleanup_rcache;
            } else {
                tl_warn(self->super.super.lib, "Created DPU rcache");
            }
        } else {
            tl_warn(self->super.super.lib, "Disabled DPU rcache");
        }
    }

    ucc_status = ucc_mpool_init(&self->req_mp, 0,
            sizeof(ucc_tl_dpu_task_t), 0, UCC_CACHE_LINE_SIZE, 8, UINT_MAX,
            &ucc_tl_dpu_req_mpool_ops, worker_params.thread_mode,
            "tl_dpu_req_mp");
    if (UCC_OK != ucc_status) {
        tl_error(self->super.super.lib, "failed to initialize tl_dpu_req mpool");
        goto err_cleanup_mpool;
    }

    self->dpu_per_node_cnt = dpu_count;

    tl_info(self->super.super.lib, "context created for %d DPUs", dpu_count);
    return ucc_status;

err_cleanup_mpool:
    ucc_mpool_cleanup(&self->req_mp, 1);
err_cleanup_rcache:
    for (i = 0; i < rail-1; i++) {
        ucc_rcache_destroy(self->dpu_ctx_list[i].rcache);
    }
err_cleanup_worker:
    for (i = 0; i < rail-1; i++) {
        ucp_worker_destroy(self->dpu_ctx_list[i].ucp_worker);
        ucp_cleanup(self->dpu_ctx_list[i].ucp_context);
    }
err_cleanup_context:
    for (i = 0; i < rail-1; i++) {
        ucp_worker_destroy(self->dpu_ctx_list[i].ucp_worker);
        ucp_cleanup(self->dpu_ctx_list[i].ucp_context);
    }

err:
    return ucc_status;
}

UCC_CLASS_CLEANUP_FUNC(ucc_tl_dpu_context_t)
{
    ucp_request_param_t param;
    ucs_status_t ucs_status;
    ucs_status_ptr_t close_req;
    int rail;

    tl_info(self->super.super.lib, "finalizing tl context: %p", self);
    
    for (rail = 0; rail < self->dpu_per_node_cnt; rail++) {
        ucc_tl_dpu_connect_t *dpu_connect = &self->dpu_ctx_list[rail];
        ucp_worker_flush(dpu_connect->ucp_worker);

        param.op_attr_mask  = UCP_OP_ATTR_FIELD_FLAGS;
        param.flags         = UCP_EP_CLOSE_FLAG_FORCE;
        close_req           = ucp_ep_close_nbx(dpu_connect->ucp_ep, &param);
        if (UCS_PTR_IS_PTR(close_req)) {
            do {
                ucp_worker_progress(dpu_connect->ucp_worker);
                ucs_status = ucp_request_check_status(close_req);
            } while (ucs_status == UCS_INPROGRESS);
            ucp_request_free (close_req);
        } else if (UCS_PTR_STATUS(close_req) != UCS_OK) {
            tl_error(self->super.super.lib, "failed to close ep %p\n", (void *)dpu_connect->ucp_ep);
        }
        if (dpu_connect->rcache) {
            ucc_rcache_destroy(dpu_connect->rcache);
        }
        ucp_worker_destroy(dpu_connect->ucp_worker);
        ucp_cleanup(dpu_connect->ucp_context);
    }

    ucc_mpool_cleanup(&self->req_mp, 1);
}

UCC_CLASS_DEFINE(ucc_tl_dpu_context_t, ucc_tl_context_t);

ucc_status_t ucc_tl_dpu_get_context_attr(const ucc_base_context_t *context,
                                         ucc_base_ctx_attr_t      *attr)
{
    if (attr->attr.mask & UCC_CONTEXT_ATTR_FIELD_CTX_ADDR_LEN) {
        attr->attr.ctx_addr_len = 0;
    }
    return UCC_OK;
}

/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "host_channel.h"
#include <unistd.h>
#include <ucc/api/ucc.h>

size_t dpu_ucc_dt_sizes[UCC_DT_USERDEFINED] = {
    [UCC_DT_INT8]    = 1,
    [UCC_DT_UINT8]   = 1,
    [UCC_DT_INT16]   = 2,
    [UCC_DT_UINT16]  = 2,
    [UCC_DT_FLOAT16] = 2,
    [UCC_DT_INT32]   = 4,
    [UCC_DT_UINT32]  = 4,
    [UCC_DT_FLOAT32] = 4,
    [UCC_DT_INT64]   = 8,
    [UCC_DT_UINT64]  = 8,
    [UCC_DT_FLOAT64] = 8,
    [UCC_DT_INT128]  = 16,
    [UCC_DT_UINT128] = 16,
};

                                  
size_t dpu_ucc_dt_size(ucc_datatype_t dt)
{
    if (dt < UCC_DT_USERDEFINED) {
        return dpu_ucc_dt_sizes[dt];
    }
    return 0;
}

static int _dpu_host_to_ip(dpu_hc_t *hc)
{
//     printf ("%s\n", __FUNCTION__);
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    hc->hname = calloc(1, 100 * sizeof(char));
    hc->ip = malloc(100 * sizeof(char));

    int ret = gethostname(hc->hname, 100);
    if (ret) {
        return 1;
    }

    if ( (he = gethostbyname( hc->hname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(hc->ip , inet_ntoa(*addr_list[i]) );
        return UCC_OK;
    }
    return UCC_ERR_NO_MESSAGE;
}

static int _dpu_listen(dpu_hc_t *hc)
{
    struct sockaddr_in serv_addr;

    if(_dpu_host_to_ip(hc)) {
        return UCC_ERR_NO_MESSAGE;
    }

    hc->port = DEFAULT_PORT;
    /* TODO: if envar(port) - replace */

    /* creates an UN-named socket inside the kernel and returns
     * an integer known as socket descriptor
     * This function takes domain/family as its first argument.
     * For Internet family of IPv4 addresses we use AF_INET
     */
    hc->listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > hc->listenfd) {
        fprintf(stderr, "socket() failed (%s)\n", strerror(errno));
        goto err_ip;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(hc->port);

    /* The call to the function "bind()" assigns the details specified
     * in the structure 『serv_addr' to the socket created in the step above
     */
    if (0 > bind(hc->listenfd, (struct sockaddr*)&serv_addr,
                 sizeof(serv_addr))) {
        fprintf(stderr, "Failed to bind() (%s)\n", strerror(errno));
        goto err_sock;
    }

    /* The call to the function "listen()" with second argument as 10 specifies
     * maximum number of client connections that server will queue for this listening
     * socket.
     */
    if (0 > listen(hc->listenfd, 10)) {
        fprintf(stderr, "listen() failed (%s)\n", strerror(errno));
        goto err_sock;
    }

    return UCC_OK;
err_sock:
    close(hc->listenfd);
err_ip:
    free(hc->ip);
    free(hc->hname);
    return UCC_ERR_NO_MESSAGE;
}

static void _dpu_listen_cleanup(dpu_hc_t *hc)
{
    DPU_LOG("Cleaning up host channel\n");
    close(hc->listenfd);
    free(hc->ip);
    free(hc->hname);
}


ucc_status_t _dpu_req_test(ucs_status_ptr_t request)
{
    if (request == NULL) {
        return UCS_OK;
    }
    else if (UCS_PTR_IS_ERR(request)) {
        fprintf (stderr, "unable to complete UCX request\n");
        return UCS_PTR_STATUS(request);
    }
    else {
        return ucp_request_check_status(request);
    }
}

static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    printf ("error handling callback was invoked with status %d (%s)\n",
            status, ucs_status_string(status));
}

static ucs_status_t _dpu_flush_host_eps(dpu_hc_t *hc)
{
    int i;
    ucp_request_param_t param = {};
    ucs_status_ptr_t request;

    for (i = 0; i < hc->world_size; i++) {
        request = ucp_ep_flush_nbx(hc->host_eps[i], &param);
        _dpu_request_wait(hc->ucp_worker, request);
    }
    return UCS_OK;
}

static ucs_status_t _dpu_worker_flush(dpu_hc_t *hc)
{
    ucp_request_param_t param = {};
    ucs_status_ptr_t request = ucp_worker_flush_nbx(hc->ucp_worker, &param);
    return _dpu_request_wait(hc->ucp_worker, request);
}

static int _dpu_ucx_init(dpu_hc_t *hc)
{
    ucp_params_t ucp_params;
    ucs_status_t status;
    ucp_worker_params_t worker_params;
    int ret = UCC_OK;

    memset(&ucp_params, 0, sizeof(ucp_params));
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES;
    ucp_params.features = UCP_FEATURE_TAG |
                          UCP_FEATURE_RMA;

    status = ucp_init(&ucp_params, NULL, &hc->ucp_ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_init(%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_MULTI;

    status = ucp_worker_create(hc->ucp_ctx, &worker_params, &hc->ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_worker_create (%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err_cleanup;
    }

    hc->worker_attr.field_mask = UCP_WORKER_ATTR_FIELD_ADDRESS |
            UCP_WORKER_ATTR_FIELD_ADDRESS_FLAGS;
    hc->worker_attr.address_flags = UCP_WORKER_ADDRESS_FLAG_NET_ONLY;
    status = ucp_worker_query (hc->ucp_worker, &hc->worker_attr);
    if (UCS_OK != status) {
        fprintf(stderr, "failed to ucp_worker_query (%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err_worker;
    }

    return ret;
err_worker:
    ucp_worker_destroy(hc->ucp_worker);
err_cleanup:
    ucp_cleanup(hc->ucp_ctx);
err:
    return ret;
}

static int _dpu_ucx_fini(dpu_hc_t *hc){
    ucp_worker_release_address(hc->ucp_worker, hc->worker_attr.address);
    ucp_worker_destroy(hc->ucp_worker);
    ucp_cleanup(hc->ucp_ctx);
}

static int _dpu_hc_buffer_alloc(dpu_hc_t *hc, dpu_mem_t *mem, size_t size)
{
    ucp_mem_map_params_t mem_params;
    ucp_mem_attr_t mem_attr;
    ucs_status_t status;
    int ret = UCC_OK;

    memset(mem, 0, sizeof(*mem));
    mem->base = calloc(size, 1);
    if (mem->base == NULL) {
        fprintf(stderr, "failed to allocate %lu bytes base %p\n", size, mem->base);
        ret = UCC_ERR_NO_MEMORY;
        goto out;
    }

    memset(&mem_params, 0, sizeof(ucp_mem_map_params_t));
    mem_params.address = mem->base;
    mem_params.length = size;

    mem_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_FLAGS |
                       UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                       UCP_MEM_MAP_PARAM_FIELD_ADDRESS;

    status = ucp_mem_map(hc->ucp_ctx, &mem_params, &mem->memh);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_mem_map (%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err_calloc;
    }

    mem_attr.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS |
                          UCP_MEM_ATTR_FIELD_LENGTH;

    status = ucp_mem_query(mem->memh, &mem_attr);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_mem_query (%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err_map;
    }
    assert(mem_attr.length == size);
    assert(mem_attr.address == mem->base);

    status = ucp_rkey_pack(hc->ucp_ctx, mem->memh,
                           &mem->rkey.rkey_addr,
                           &mem->rkey.rkey_addr_len);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_rkey_pack (%s)\n", ucs_status_string(status));
        ret = UCC_ERR_NO_MESSAGE;
        goto err_map;
    }
    
    goto out;
err_map:
    ucp_mem_unmap(hc->ucp_ctx, mem->memh);
err_calloc:
    free(mem->base);
out:
    return ret;
}

static int _dpu_hc_buffer_free(dpu_hc_t *hc, dpu_mem_t *mem)
{
    ucp_rkey_buffer_release(mem->rkey.rkey_addr);
    ucp_mem_unmap(hc->ucp_ctx, mem->memh);
    free(mem->base);
}

static void _dpu_hc_reset_buf(dpu_buf_t *buf)
{
    buf->state = FREE;
    buf->count = 0;
    buf->ucp_req = NULL;
}

static void _dpu_hc_reset_stage(dpu_stage_t *stage, dpu_hc_t *hc)
{
    stage->phase = WAIT;
    stage->get_idx = stage->red_idx = 0;
    stage->src_rank = stage->dst_rank = hc->world_rank / hc->dpu_per_node_cnt;
    stage->done_get = stage->done_red = stage->done_put = 0;
    _dpu_hc_reset_buf(&stage->accbuf);
    _dpu_hc_reset_buf(&stage->getbuf[0]);
    _dpu_hc_reset_buf(&stage->getbuf[1]);
}

static void _dpu_hc_reset_pipeline(dpu_hc_t *hc)
{
    dpu_pipeline_t *pipe = &hc->pipeline;
    _dpu_hc_reset_stage(&pipe->stages[0], hc);
    _dpu_hc_reset_stage(&pipe->stages[1], hc);
    pipe->my_count = pipe->my_offset = 0;
    pipe->count_received = pipe->count_reduced = pipe->count_serviced = 0;

    /* Kickstart */
    pipe->stages[0].phase = INIT;
}

static  int _dpu_hc_init_pipeline(dpu_hc_t *hc)
{
    int i, ret;

    assert(hc->pipeline.buffer_size > 0);
    assert(hc->pipeline.num_buffers > 0);

    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.in, hc->pipeline.buffer_size * 3);
    if (ret) {
        goto out;
    }
    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.out, hc->pipeline.buffer_size * 3);
    if (ret) {
        goto err_put;
    }
    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.sync, sizeof(dpu_put_sync_t));
    if (ret) {
        goto err_get;
    }

    hc->pipeline.stages[0].accbuf.buf    = (char *)hc->mem_segs.in.base + hc->pipeline.buffer_size * 0;
    hc->pipeline.stages[0].getbuf[0].buf = (char *)hc->mem_segs.in.base + hc->pipeline.buffer_size * 1;
    hc->pipeline.stages[0].getbuf[1].buf = (char *)hc->mem_segs.in.base + hc->pipeline.buffer_size * 2;

    hc->pipeline.stages[1].accbuf.buf    = (char *)hc->mem_segs.out.base + hc->pipeline.buffer_size * 0;
    hc->pipeline.stages[1].getbuf[0].buf = (char *)hc->mem_segs.out.base + hc->pipeline.buffer_size * 1;
    hc->pipeline.stages[1].getbuf[1].buf = (char *)hc->mem_segs.out.base + hc->pipeline.buffer_size * 2;

    _dpu_hc_reset_pipeline(hc);
    goto out;
err_get:
    _dpu_hc_buffer_free(hc, &hc->mem_segs.out);
err_put:
    _dpu_hc_buffer_free(hc, &hc->mem_segs.in);
out:
    return ret;
}

int dpu_hc_init(dpu_hc_t *hc)
{
    int ret = UCC_OK;

    memset(hc, 0, sizeof(*hc));
    MPI_Comm_rank(MPI_COMM_WORLD, &hc->world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &hc->world_size);

    /* Start listening */
    ret = _dpu_listen(hc);
    if (ret) {
        goto out;
    }
    
    /* init ucx objects */
    ret = _dpu_ucx_init(hc);
    if (ret) {
        goto err_ip;
    }

    goto out;
err_ucx:
    _dpu_ucx_fini(hc);
err_ip:
    _dpu_listen_cleanup(hc);
out:
    return ret;
}

static ucs_status_t _dpu_create_host_eps(dpu_hc_t *hc, void *rem_worker_addr, size_t rem_worker_addr_len)
{
    ucs_status_t status;
    ucp_ep_params_t ep_params;
    int i;
    void *remote_addrs = NULL;

    /* Connect to all remote hosts */
    hc->host_eps = calloc(hc->world_size, sizeof(ucp_ep_h));
    remote_addrs = calloc(hc->world_size, rem_worker_addr_len);
    MPI_Allgather(rem_worker_addr, rem_worker_addr_len, MPI_BYTE,
                  remote_addrs, rem_worker_addr_len, MPI_BYTE, MPI_COMM_WORLD);

    ep_params.field_mask    = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                              UCP_EP_PARAM_FIELD_ERR_HANDLER |
                              UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode		= UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb    = err_cb;

    for (i = 0; i < hc->world_size; i++) {
        ep_params.address = remote_addrs + i * rem_worker_addr_len;
        status = ucp_ep_create(hc->ucp_worker, &ep_params, &hc->host_eps[i]);
        if (status != UCS_OK) {
            fprintf(stderr, "failed to create endpoint on dpu to host %d (%s)\n",
                    i, ucs_status_string(status));
            return UCC_ERR_NO_MESSAGE;
        }
    }

    hc->localhost_ep = hc->host_eps[hc->world_rank];
    hc->host_rkeys = calloc(hc->world_size, sizeof(host_rkey_t));
    hc->host_src_rkeys = calloc(hc->world_size, sizeof(ucp_rkey_h));
    hc->host_dst_rkeys = calloc(hc->world_size, sizeof(ucp_rkey_h));
    hc->world_lsyncs = calloc(hc->world_size, sizeof(dpu_put_sync_t));
    
    memset(&hc->req_param, 0, sizeof(hc->req_param));
    // hc->req_param.op_attr_mask = UCP_OP_ATTR_FLAG_NO_IMM_CMPL;

    return UCC_OK;
}

static int _dpu_close_host_eps(dpu_hc_t *hc)
{
    ucp_request_param_t param;
    ucs_status_t status;
    void *close_req;
    int ret = UCC_OK;
    int i;

    param.op_attr_mask  = UCP_OP_ATTR_FIELD_FLAGS;
    param.flags         = UCP_EP_CLOSE_FLAG_FORCE;

    for (i = 0; i < hc->world_size; i++) {
        close_req = ucp_ep_close_nbx(hc->host_eps[i], &param);
        if (UCS_PTR_IS_PTR(close_req)) {
            do {
                ucp_worker_progress(hc->ucp_worker);
                status = ucp_request_check_status(close_req);
            } while (status == UCS_INPROGRESS);

            ucp_request_free(close_req);
        }
        else if (UCS_PTR_STATUS(close_req) != UCS_OK) {
            fprintf(stderr, "failed to close ep %p\n", (void *)hc->host_eps[i]);
            ret = UCC_ERR_NO_MESSAGE;
        }
    }
    free(hc->host_eps);
    free(hc->host_rkeys);
    free(hc->host_src_rkeys);
    free(hc->host_dst_rkeys);
    return ret;
}

ucs_status_t _dpu_request_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t request)
{
    ucs_status_t status;

    /* immediate completion */
    if (request == NULL) {
        return UCS_OK;
    }
    else if (UCS_PTR_IS_ERR(request)) {
        status = ucp_request_check_status(request);
        fprintf (stderr, "unable to complete UCX request (%s)\n", ucs_status_string(status));
        return UCS_PTR_STATUS(request);
    }
    else {
        do {
            ucp_worker_progress(ucp_worker);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(request);
    }

    return status;
}

int dpu_hc_accept(dpu_hc_t *hc)
{
    int ret;
    ucs_status_t status;
    ucp_rkey_h client_rkey_h;
    void *rem_worker_addr;
    size_t rem_worker_addr_len;

    /* In the call to accept(), the server is put to sleep and when for an incoming
         * client request, the three way TCP handshake* is complete, the function accept()
         * wakes up and returns the socket descriptor representing the client socket.
         */
//     fprintf (stderr, "Waiting for connection...\n");
    hc->connfd = accept(hc->listenfd, (struct sockaddr*)NULL, NULL);
    if (-1 == hc->connfd) {
        fprintf(stderr, "Error in accept (%s)!\n", strerror(errno));
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }
//     fprintf (stderr, "Connection established\n");

    ret = send(hc->connfd, &hc->worker_attr.address_length, sizeof(size_t), 0);
    if (-1 == ret) {
        fprintf(stderr, "send worker_address_length failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    ret = send(hc->connfd, hc->worker_attr.address,
               hc->worker_attr.address_length, 0);
    if (-1 == ret) {
        fprintf(stderr, "send worker_address failed!\n");
        fprintf(stderr, "mmap_buffer failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    ret = recv(hc->connfd, &rem_worker_addr_len, sizeof(size_t), MSG_WAITALL);
    if (-1 == ret) {
        fprintf(stderr, "recv address_length failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    rem_worker_addr = calloc(1, rem_worker_addr_len);

    ret = recv(hc->connfd, rem_worker_addr, rem_worker_addr_len, MSG_WAITALL);
    if (-1 == ret) {
        fprintf(stderr, "recv worker address failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    if (ret = _dpu_create_host_eps(hc, rem_worker_addr, rem_worker_addr_len)) {
        fprintf(stderr, "_dpu_create_host_eps failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    memset(&hc->pipeline, 0, sizeof(hc->pipeline));

    ret = recv(hc->connfd, &hc->pipeline.buffer_size, sizeof(size_t), MSG_WAITALL);
    if (-1 == ret) {
        fprintf(stderr, "recv pipeline buffer size failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    ret = recv(hc->connfd, &hc->pipeline.num_buffers, sizeof(size_t), MSG_WAITALL);
    if (-1 == ret) {
        fprintf(stderr, "recv pipeline num buffers failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    ret = _dpu_hc_init_pipeline(hc);
    if (ret) {
        fprintf(stderr, "init pipeline failed!\n");
        goto err;
    }

    ret = _dpu_flush_host_eps(hc);
    if (ret) {
        fprintf(stderr, "ep flush failed!\n");
        goto err;
    }
    return ret;

err:
    close(hc->connfd);
    return ret;
}

int dpu_hc_wait(dpu_hc_t *hc, unsigned int next_coll_id)
{
    dpu_put_sync_t *lsync = (dpu_put_sync_t*)hc->mem_segs.sync.base;
    ucp_request_param_t req_param = {0};
    ucp_tag_t req_tag = 0, tag_mask = 0;
    ucs_status_t status;

    ucs_status_ptr_t recv_req = ucp_tag_recv_nbx(hc->ucp_worker,
            lsync, sizeof(dpu_put_sync_t),
            req_tag, tag_mask, &req_param);
    status = _dpu_request_wait(hc->ucp_worker, recv_req);

    DPU_LOG("Got next coll id from host: %u was expecting %u\n", lsync->coll_id, next_coll_id);
    assert(lsync->coll_id == next_coll_id);

    host_rkey_t *rkeys = &lsync->rkeys;

    status = ucp_ep_rkey_unpack(hc->localhost_ep, (void*)rkeys->src_rkey_buf, &hc->src_rkey);

    status = ucp_ep_rkey_unpack(hc->localhost_ep, (void*)rkeys->dst_rkey_buf, &hc->dst_rkey);

    return 0;
}

int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync)
{
    ucs_status_t status;
    ucp_tag_t req_tag = 0;

    DPU_LOG("Flushing host ep for coll_id: %d\n", coll_sync->coll_id);
    _dpu_worker_flush(hc);

    assert(hc->pipeline.sync_req == NULL);
    ucp_worker_fence(hc->ucp_worker);
    DPU_LOG("Notify host completed coll_id: %d, serviced: %lu\n",
            coll_sync->coll_id, coll_sync->count_serviced);
    hc->pipeline.sync_req = ucp_tag_send_nbx(hc->localhost_ep,
            coll_sync, sizeof(dpu_get_sync_t), req_tag, &hc->req_param);
    status = _dpu_request_wait(hc->ucp_worker, hc->pipeline.sync_req);
    hc->pipeline.sync_req = NULL;
    if (status != UCS_OK) {
        fprintf(stderr, "failed to notify host of completion (%s)\n", ucs_status_string(status));
        return -1;
    }

    ucp_rkey_destroy(hc->src_rkey);
    ucp_rkey_destroy(hc->dst_rkey);
    _dpu_hc_reset_pipeline(hc);
    return 0;
}

ucs_status_t dpu_hc_issue_get(dpu_hc_t *hc, dpu_put_sync_t *sync, dpu_stage_t *stage, dpu_buf_t *getbuf)
{
    assert(stage->phase == INIT || stage->phase == REDUCE);
    assert(getbuf->state == FREE && getbuf->ucp_req == NULL);
    getbuf->state = SENDRECV;

    ucc_datatype_t dtype = sync->coll_args.src.info.datatype;
    size_t dt_size = dpu_ucc_dt_size(dtype);
    size_t remaining_elems = hc->pipeline.my_count - hc->pipeline.count_received;
    size_t count = DPU_MIN(hc->pipeline.buffer_size/dt_size, remaining_elems);
    size_t get_offset = hc->pipeline.my_offset + hc->pipeline.count_received * dt_size;
    int src_rank = stage->src_rank;
    int ep_src_rank = src_rank * hc->dpu_per_node_cnt + 
        (hc->world_rank % hc->dpu_per_node_cnt);
    getbuf->count = count;

    if (0 == count) {
        return UCS_ERR_NO_RESOURCE;
    }

    size_t data_size = count * dt_size;
    void *src_addr = hc->host_rkeys[ep_src_rank].src_buf + get_offset;
    void *dst_addr = getbuf->buf;

    DPU_LOG("Issue Get from %d offset %lu src %p dst %p count %lu bytes %lu\n",
            src_rank, get_offset, src_addr, dst_addr, count, data_size);
    
    ucp_worker_fence(hc->ucp_worker);
    getbuf->ucp_req =
            ucp_get_nbx(hc->host_eps[ep_src_rank], dst_addr, data_size,
            (uint64_t)src_addr, hc->host_src_rkeys[ep_src_rank], &hc->req_param);
    
    stage->src_rank = (src_rank + 1) % (hc->world_size / hc->dpu_per_node_cnt); // FIXME team size
    return UCS_OK;
}

ucs_status_t dpu_hc_issue_put(dpu_hc_t *hc, dpu_put_sync_t *sync, dpu_stage_t *stage, dpu_buf_t *accbuf)
{
    assert(stage->phase == BCAST);
    assert(accbuf->state == IDLE && accbuf->ucp_req == NULL);
    accbuf->state = SENDRECV;

    ucc_datatype_t dtype = sync->coll_args.src.info.datatype;
    size_t dt_size = dpu_ucc_dt_size(dtype);
    size_t count = accbuf->count;
    size_t put_offset = hc->pipeline.my_offset + hc->pipeline.count_serviced * dt_size;
    int dst_rank = stage->dst_rank;
    int ep_dst_rank = dst_rank * hc->dpu_per_node_cnt + 
        (hc->world_rank % hc->dpu_per_node_cnt);


    size_t data_size = count * dt_size;
    void *src_addr = accbuf->buf;
    void *dst_addr = hc->host_rkeys[ep_dst_rank].dst_buf + put_offset;

    DPU_LOG("Issue Put to %d offset %lu src %p dst %p count %lu bytes %lu\n",
            dst_rank, put_offset, src_addr, dst_addr, count, data_size);
    assert(count > 0 && dt_size > 0 && accbuf->ucp_req == NULL);

    int32_t *pbuf = accbuf->buf;
    DPU_LOG("## PUT DATA %ld %ld\n", pbuf[0], pbuf[1]);
    
    ucp_worker_fence(hc->ucp_worker);
    accbuf->ucp_req =
            ucp_put_nbx(hc->host_eps[ep_dst_rank], src_addr, data_size,
            (uint64_t)dst_addr, hc->host_dst_rkeys[ep_dst_rank], &hc->req_param);

    stage->dst_rank = (dst_rank + 1) % (hc->world_size / hc->dpu_per_node_cnt); // FIXME team size
    return UCS_OK;
}

ucs_status_t dpu_hc_issue_allreduce(dpu_hc_t *hc, thread_ctx_t *ctx, dpu_stage_t *stage, dpu_buf_t *accbuf, dpu_buf_t *getbuf)
{
    assert(stage->phase == REDUCE);
    assert(accbuf->state == IDLE && accbuf->ucp_req == NULL);
    assert(getbuf->state == IDLE && getbuf->ucp_req == NULL);
    assert(accbuf->count == getbuf->count);

    accbuf->state = REDUCING;
    getbuf->state = REDUCING;
    thread_sub_sync->accbuf = accbuf;
    thread_sub_sync->getbuf = getbuf;

    int32_t *buf1 = accbuf->buf;
    int32_t *buf2 = getbuf->buf;
    DPU_LOG("## B4 REDUCE ACC DATA %ld %ld GET DATA %ld %ld\n", buf1[0], buf1[1], buf2[0], buf2[1]);

    DPU_LOG("Issue AR accbuf %p getbuf %p count %lu\n", accbuf->buf, getbuf->buf, accbuf->count);
    dpu_signal_comp_thread(ctx, thread_sub_sync);

    return UCS_OK;
}

ucs_status_t dpu_hc_issue_hangup(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx)
{
    thread_sub_sync->accbuf = NULL;
    thread_sub_sync->getbuf = NULL;
    dpu_signal_comp_thread(ctx, thread_sub_sync);
    return UCS_OK;
}

ucc_status_t dpu_check_comp_status(thread_ctx_t *ctx, thread_sync_t *sync)
{
    int i;
    if(!sync->accbuf || !sync->getbuf) {
        return UCC_ERR_INVALID_PARAM;
    }
    if (!sync->done) {
            return UCC_INPROGRESS;
    }
    return UCC_OK;
}

ucs_status_t dpu_hc_progress_allreduce(dpu_hc_t *hc,
                    dpu_put_sync_t *sync,
                    thread_ctx_t *ctx)
{
    int i, j;
    ucc_status_t status;
    ucs_status_ptr_t request;
    dpu_pipeline_t *pp = &hc->pipeline;
    /* TODO change the ranks to represent the team size, also change the name
     * */
    int ranks = (hc->world_size / hc->dpu_per_node_cnt);

    for (i=0; i<10; i++) {
        if (ucp_worker_progress(hc->ucp_worker)) {
            break;
        }
    }

    dpu_stage_t *stage = &pp->stages[0];
    dpu_buf_t *accbuf = &stage->accbuf;
    dpu_buf_t *getbuf = &stage->getbuf[stage->get_idx];
    dpu_buf_t *redbuf = &stage->getbuf[stage->red_idx];

    switch(stage->phase) {
        case INIT:
        if (accbuf->state == FREE) {
            assert(stage->done_get == 0);
            dpu_hc_issue_get(hc, sync, stage, accbuf);
        } else if (accbuf->state == SENDRECV && accbuf->count > 0) {
            request = accbuf->ucp_req;
            if (_dpu_req_test(request) == UCS_OK) {
                if (request) ucp_request_free(request);
                accbuf->ucp_req = NULL;
                accbuf->state = IDLE;
                stage->done_get += 1;
                stage->phase = REDUCE;
                DPU_LOG("Stage %d Received %ld bytes into accbuf, gets done %d\n",
                        i, accbuf->count, stage->done_get);
            }
        }
        break;
        case REDUCE:
        if (getbuf->state == FREE && stage->done_get < ranks) {
            assert(stage->done_get > 0);
            dpu_hc_issue_get(hc, sync, stage, getbuf);
            // assert(getbuf->ucp_req != NULL);
        } else if (getbuf->state == SENDRECV && getbuf->count > 0) {
            request = getbuf->ucp_req;
            if (_dpu_req_test(request) == UCS_OK) {
                if (request) ucp_request_free(request);
                getbuf->ucp_req = NULL;
                getbuf->state = IDLE;
                stage->done_get += 1;
                DPU_LOG("Stage %d Received %ld bytes into getbuf[%d], gets done %d\n",
                        i, getbuf->count, stage->get_idx, stage->done_get);

                if (stage->done_get == ranks) {
                    pp->count_received += accbuf->count;
                    /* Allow next stage to start */
                    // int other = (i+1) % 2;
                    // dpu_stage_t *next_stage = &pp->stages[other];
                    // DPU_LOG("Next stage %d, state %d\n", other, next_stage->phase);
                    // assert(next_stage->phase == WAIT);
                    // next_stage->phase = INIT;
                }
            }
        }
        if (getbuf->state == IDLE && accbuf->state == IDLE) {
            assert(stage->done_get > stage->done_red);
            dpu_hc_issue_allreduce(hc, ctx, stage, accbuf, getbuf);
            /* Swap Reduce and Get buffers */
            stage->red_idx = stage->get_idx;
            stage->get_idx = (stage->get_idx + 1) % 2;
        }
        if (redbuf->state == REDUCING && accbuf->state == REDUCING) {
            /* Check for reduce completion */
            if (dpu_check_comp_status(ctx, thread_sub_sync) == UCC_OK) {
                redbuf->state = FREE;
                accbuf->state = IDLE;
                stage->done_red += 1;
                DPU_LOG("Stage %d reduced %ld bytes from getbuf[%d], reds done %d\n",
                        i, redbuf->count, stage->red_idx, stage->done_red);
                thread_sub_sync->accbuf = thread_sub_sync->getbuf = NULL;

                if (stage->done_red == ranks-1) {
                    /* Start broadcast */
                    stage->phase = BCAST;
                    pp->count_reduced += accbuf->count;
                }
            }
        }
        break;
        case BCAST:
        if (accbuf->state == IDLE && accbuf->count > 0) {
            DPU_LOG("Ranks %d Stage %d done get %d red %d put %d\n", ranks, i, stage->done_get, stage->done_red, stage->done_put);
            assert(stage->done_get == ranks);
            assert(stage->done_red == ranks-1);
            assert(stage->done_put <= ranks);
            dpu_hc_issue_put(hc, sync, stage, accbuf);
            // assert(accbuf->ucp_req != NULL);
        } else if (accbuf->state == SENDRECV && accbuf->count > 0) {
            request = accbuf->ucp_req;
            if (_dpu_req_test(request) == UCS_OK) {
                if (request) ucp_request_free(request);
                accbuf->ucp_req = NULL;
                accbuf->state = IDLE;
                stage->done_put += 1;
                DPU_LOG("Stage %d sent %ld bytes from accbuf, puts done %d\n",
                        i, accbuf->count, stage->done_put);
                
                if (stage->done_put == ranks) {
                    /* Done with this stage */
                    pp->count_serviced += accbuf->count;
                    stage->phase = WAIT;

                    /* Reset this stage counters */
                    _dpu_hc_reset_stage(stage, hc);

                    /* Allow next stage to start */
                    int next = 0; //(i+1) % 2;
                    dpu_stage_t *next_stage = &pp->stages[next];
                    DPU_LOG("Next stage %d, state %d\n", next, next_stage->phase);
                    assert(next_stage->phase == WAIT);
                    next_stage->phase = INIT;
                }
            }
        } else {
            DPU_LOG("Impossible!! stage %d %p phase %d state %d\n", i, stage, stage->phase, accbuf->state);
            assert(0);
        }
        break;
        default:
        break;
    }

}

int dpu_hc_finalize(dpu_hc_t *hc)
{
    _dpu_flush_host_eps(hc);
    _dpu_worker_flush(hc);
    _dpu_listen_cleanup(hc);
    _dpu_hc_buffer_free(hc, &hc->mem_segs.in);
    _dpu_hc_buffer_free(hc, &hc->mem_segs.out);
    _dpu_hc_buffer_free(hc, &hc->mem_segs.sync);
    _dpu_close_host_eps(hc);
    _dpu_ucx_fini(hc);
    return UCC_OK;
}

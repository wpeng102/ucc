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

static ucs_status_t _dpu_request_wait (ucp_worker_h ucp_worker, ucs_status_ptr_t *request);
                                  
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

static int _dpu_listen_cleanup(dpu_hc_t *hc)
{
    close(hc->listenfd);
    free(hc->ip);
    free(hc->hname);
}

ucc_status_t _dpu_req_test(ucs_status_ptr_t *request)
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

inline
ucc_status_t _dpu_req_check(ucs_status_ptr_t *req)
{
    if (UCS_PTR_IS_ERR(req)) {
        fprintf(stderr, "failed to send/recv msg\n");
        return UCC_ERR_NO_MESSAGE;
    }
    return UCC_OK;
}

static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    printf ("error handling callback was invoked with status %d (%s)\n",
            status, ucs_status_string(status));
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
    mem->base = calloc(size, sizeof(char));
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
        goto out;
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

static  int _dpu_hc_init_pipeline(dpu_hc_t *hc)
{
    int i, ret;

    memset(&hc->pipeline, 0, sizeof(hc->pipeline));
    hc->pipeline.buffer_size = 1l * 1024 * 1024;
    hc->pipeline.num_buffers = 2;
    fprintf(stderr, "buffer_size: %lu, num_buffers: %lu\n", hc->pipeline.buffer_size, hc->pipeline.num_buffers);

    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.in, hc->pipeline.buffer_size * hc->pipeline.num_buffers);
    if (ret) {
        goto out;
    }
    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.out, hc->pipeline.buffer_size * hc->pipeline.num_buffers);
    if (ret) {
        goto err_put;
    }
    ret = _dpu_hc_buffer_alloc(hc, &hc->mem_segs.sync, sizeof(dpu_put_sync_t));
    if (ret) {
        goto err_get;
    }

    for (i=0; i<hc->pipeline.num_buffers; i++) {
        hc->pipeline.stage[i].get.buf = (char *)hc->mem_segs.in.base  + hc->pipeline.buffer_size * i;
        hc->pipeline.stage[i].put.buf = (char *)hc->mem_segs.out.base + hc->pipeline.buffer_size * i;
    }

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

static ucs_status_t _dpu_ep_create (dpu_hc_t *hc, void *rem_worker_addr)
{
    ucs_status_t status;
    ucp_ep_params_t ep_params;

    ep_params.field_mask    = UCP_EP_PARAM_FIELD_FLAGS |
                              UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                              UCP_EP_PARAM_FIELD_ERR_HANDLER |
                              UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode		= UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb    = err_cb;
    ep_params.address = rem_worker_addr;

    status = ucp_ep_create(hc->ucp_worker, &ep_params, &hc->host_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to create an endpoint on the dpu (%s)\n",
                ucs_status_string(status));
        return UCC_ERR_NO_MESSAGE;
    }

    memset(&hc->req_param, 0, sizeof(hc->req_param));
    return UCC_OK;
}

static int _dpu_ep_close(dpu_hc_t *hc)
{
    ucp_request_param_t param;
    ucs_status_t status;
    void *close_req;
    int ret = UCC_OK;

    param.op_attr_mask  = UCP_OP_ATTR_FIELD_FLAGS;
    param.flags         = UCP_EP_CLOSE_FLAG_FORCE;
    close_req           = ucp_ep_close_nbx(hc->host_ep, &param);
    if (UCS_PTR_IS_PTR(close_req)) {
        do {
            ucp_worker_progress(hc->ucp_worker);
            status = ucp_request_check_status(close_req);
        } while (status == UCS_INPROGRESS);

        ucp_request_free(close_req);
    } else if (UCS_PTR_STATUS(close_req) != UCS_OK) {
        fprintf(stderr, "failed to close ep %p\n", (void *)hc->host_ep);
        ret = UCC_ERR_NO_MESSAGE;
    }
    return ret;
}


static ucs_status_t _dpu_request_wait(ucp_worker_h ucp_worker, ucs_status_ptr_t *request)
{
    ucs_status_t status;

    /* immediate completion */
    if (request == NULL) {
        return UCS_OK;
    }
    else if (UCS_PTR_IS_ERR(request)) {
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

static int _dpu_rmem_setup(dpu_hc_t *hc)
{
    int i;
    ucs_status_t status;
    ucp_request_param_t *param = &hc->req_param;
    ucs_status_ptr_t *request;
    size_t rkeys_total_len = 0, rkey_lens[3];
    uint64_t seg_base_addrs[3];
    char *rkeys = NULL, *rkey_p;

    request = ucp_tag_recv_nbx(hc->ucp_worker, &hc->sync_addr, sizeof(uint64_t),
                                      EXCHANGE_ADDR_TAG, (uint64_t)-1, param);
    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to recv sync addr (%s)\n", ucs_status_string(status));
        goto err;
    }

    request = ucp_tag_recv_nbx(hc->ucp_worker, &rkey_lens[0], sizeof(size_t),
                                      EXCHANGE_LENGTH_TAG, (uint64_t)-1, param);
    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to recv rkey lens (%s)\n", ucs_status_string(status));
        goto err;
    }

    rkeys = calloc(1, rkey_lens[0]);
    request = ucp_tag_recv_nbx(hc->ucp_worker, rkeys, rkey_lens[0], EXCHANGE_RKEY_TAG,
                               (uint64_t)-1, param);

    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to recv hosyt rkeys (%s)\n", ucs_status_string(status));
        goto err;
    }

    status = ucp_ep_rkey_unpack(hc->host_ep, rkeys, &hc->sync_rkey);
    if (status) {
        fprintf(stderr, "failed to ucp_ep_rkey_unpack (%s)\n", ucs_status_string(status));
    }
    free(rkeys);

    /* compute total len */
    for (i = 0; i < 3; i++) {
        rkey_lens[i] = hc->mem_segs_array[i].rkey.rkey_addr_len;
        seg_base_addrs[i] = (uint64_t)hc->mem_segs_array[i].base;
        rkeys_total_len += rkey_lens[i];
//         fprintf (stdout, "rkey_total_len = %lu, rkey_lens[i] = %lu\n",
//                  rkeys_total_len, rkey_lens[i]);
    }

    rkey_p = rkeys = calloc(1, rkeys_total_len);

    /* send rkey_lens */
    request = ucp_tag_send_nbx(hc->host_ep, rkey_lens, 3*sizeof(size_t),
                                     EXCHANGE_LENGTH_TAG, param);
    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to send rkey lens (%s)\n", ucs_status_string(status));
        goto err;
    }

    request = ucp_tag_send_nbx(hc->host_ep, seg_base_addrs, 3*sizeof(uint64_t),
                                     EXCHANGE_ADDR_TAG, param);
    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to segment base addrs (%s)\n", ucs_status_string(status));
        goto err;
    }

    /* send rkeys */
    for (i = 0; i < 3; i++) {
        memcpy(rkey_p, hc->mem_segs_array[i].rkey.rkey_addr, rkey_lens[i]);
        rkey_p+=rkey_lens[i];
    }

    request = ucp_tag_send_nbx(hc->host_ep, rkeys, rkeys_total_len, EXCHANGE_RKEY_TAG, param);
    status = _dpu_request_wait(hc->ucp_worker, request);
    if (status) {
        fprintf(stderr, "failed to send dpu rkeys (%s)\n", ucs_status_string(status));
        goto err;
    }

    return SUCCESS;

err:
    printf ("%s ERROR!\n", __FUNCTION__);
    return ERROR;
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

    if (ret = _dpu_ep_create(hc, rem_worker_addr)) {
        fprintf(stderr, "dpu_create_ep failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }

    /*ret = recv(hc->connfd, &hc->pipeline, sizeof(hc->pipeline), MSG_WAITALL);
    if (-1 == ret) {
        fprintf(stderr, "recv pipeline info failed!\n");
        ret = UCC_ERR_NO_MESSAGE;
        goto err;
    }*/

    ret = _dpu_hc_init_pipeline(hc);
    if (ret) {
        fprintf(stderr, "init pipeline failed!\n");
        goto err;
    }

    ret = _dpu_rmem_setup(hc);
    if (ret) {
        fprintf(stderr, "exchange data failed!\n");
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

    while( lsync->coll_id < next_coll_id) {
        ucp_worker_progress(hc->ucp_worker);
        __sync_synchronize();
    }

    host_rkey_t *rkeys = &lsync->rkeys;
    ucs_status_t status;

    status = ucp_ep_rkey_unpack(hc->host_ep, (void*)rkeys->src_rkey_buf, &hc->src_rkey);

    status = ucp_ep_rkey_unpack(hc->host_ep, (void*)rkeys->dst_rkey_buf, &hc->dst_rkey);

    return 0;
}

void dpu_hc_reset_stage(dpu_stage_t *stage)
{
    stage->get.count = 0;
    stage->put.count = 0;
    stage->ar.count  = 0;
    stage->get.state = FREE;
    stage->put.state = FREE;
    stage->ar.state  = FREE;
    stage->get.ucp_req = NULL;
    stage->put.ucp_req = NULL;
}

void dpu_hc_reset_pipeline(dpu_hc_t *hc)
{
    int i;
    dpu_pipeline_t *pipe = &hc->pipeline;
    pipe->count_get.done   = 0;
    pipe->count_get.issued = 0;
    pipe->count_put.done   = 0;
    pipe->count_put.issued = 0;
    pipe->count_red.done   = 0;
    pipe->count_red.issued = 0;
    pipe->idx.get = 0;
    pipe->idx.put = 0;
    pipe->idx.ar  = 0;
    pipe->inflight.get = 0;
    pipe->inflight.put = 0;
    pipe->inflight.ar  = 0;
    for (i=0; i<pipe->num_buffers; i++) {
        dpu_hc_reset_stage(&pipe->stage[i]);
    }
}

int dpu_hc_reply(dpu_hc_t *hc, dpu_get_sync_t *coll_sync)
{
    ucs_status_t status;
    dpu_put_sync_t *lsync = (dpu_put_sync_t*)hc->mem_segs.sync.base;
    memset(lsync, 0, sizeof(dpu_put_sync_t));
    dpu_hc_reset_pipeline(hc);
    __sync_synchronize();

    assert(hc->pipeline.sync_req == NULL);
    DPU_LOG("Notify host completed coll_id: %d, serviced: %lu\n", coll_sync->coll_id, coll_sync->count_serviced);
    hc->pipeline.sync_req = ucp_put_nbx(hc->host_ep, coll_sync, sizeof(dpu_get_sync_t),
                          hc->sync_addr, hc->sync_rkey,
                          &hc->req_param);
    status = _dpu_request_wait(hc->ucp_worker, hc->pipeline.sync_req);
    hc->pipeline.sync_req = NULL;
    if (status != UCS_OK) {
        fprintf(stderr, "failed to notify host of completion (%s)\n", ucs_status_string(status));
        return -1;
    }
    
    return 0;
}

ucs_status_t dpu_hc_issue_get(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx)
{
    int get_idx = hc->pipeline.idx.get;
    dpu_pipeline_stage_state_t state = hc->pipeline.stage[get_idx].get.state;
    size_t remaining = sync->count_total - hc->pipeline.count_get.issued;
    if (state != FREE || remaining <= 0) {
        return UCS_ERR_NO_RESOURCE;
    }
    hc->pipeline.inflight.get++;
    hc->pipeline.stage[get_idx].get.state = IN_PROGRESS;
    hc->pipeline.idx.get = (get_idx + 1) % hc->pipeline.num_buffers;

    size_t dt_size = dpu_ucc_dt_size(sync->dtype);
    size_t max_elems = hc->pipeline.buffer_size/dt_size;
    size_t count = DPU_MIN(max_elems, remaining);
    size_t data_size = count * dt_size;
    void *src_addr = sync->rkeys.src_buf + hc->pipeline.count_get.issued * dt_size;
    void *dst_addr = hc->pipeline.stage[get_idx].get.buf;

    DPU_LOG("Issue Get idx %d count %lu total issued %zu src %p dst %p bytes %lu\n",
            get_idx, count, hc->pipeline.count_get.issued, src_addr, dst_addr, data_size);
    assert(count > 0);
    assert(hc->pipeline.stage[get_idx].ar.state != IN_PROGRESS);
    assert(hc->pipeline.stage[get_idx].get.ucp_req == NULL);

    hc->pipeline.stage[get_idx].get.ucp_req =
            ucp_get_nbx(hc->host_ep, dst_addr, data_size,
            (uint64_t)src_addr, hc->src_rkey, &hc->req_param);

    hc->pipeline.count_get.issued += count;
    hc->pipeline.stage[get_idx].get.count = count;
    return UCS_OK;
}

ucs_status_t dpu_hc_issue_put(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx)
{
    int put_idx = hc->pipeline.idx.put;
    dpu_pipeline_stage_state_t state = hc->pipeline.stage[put_idx].ar.state;
    if (state != DONE) {
        return UCS_ERR_NO_RESOURCE;
    }
    hc->pipeline.inflight.put++;
    hc->pipeline.stage[put_idx].put.state = IN_PROGRESS;
    hc->pipeline.idx.put = (put_idx + 1) % hc->pipeline.num_buffers;

    size_t dt_size = dpu_ucc_dt_size(sync->dtype);
    size_t count = hc->pipeline.stage[put_idx].ar.count;
    size_t data_size = count * dt_size;
    void *src_addr = hc->pipeline.stage[put_idx].put.buf;
    void *dst_addr = sync->rkeys.dst_buf + hc->pipeline.count_put.issued * dt_size;

    DPU_LOG("Issue Put idx %d count %lu total issued %zu src %p dst %p bytes %lu\n",
            put_idx, count, hc->pipeline.count_put.issued, src_addr, dst_addr, data_size);
    assert(count > 0);
    assert(hc->pipeline.stage[put_idx].put.ucp_req == NULL);

    hc->pipeline.stage[put_idx].put.ucp_req =
            ucp_put_nbx(hc->host_ep, src_addr, data_size,
            (uint64_t)dst_addr, hc->dst_rkey, &hc->req_param);
    
    hc->pipeline.count_put.issued += count;
    hc->pipeline.stage[put_idx].put.count = count;
    hc->pipeline.stage[put_idx].ar.state = FREE;
    return UCS_OK;
}

ucs_status_t dpu_hc_issue_allreduce(dpu_hc_t *hc, dpu_put_sync_t *sync, thread_ctx_t *ctx)
{
    int ar_idx = hc->pipeline.idx.ar;
    dpu_pipeline_stage_state_t get_state = hc->pipeline.stage[ar_idx].get.state;
    dpu_pipeline_stage_state_t put_state = hc->pipeline.stage[ar_idx].put.state;
    if (hc->pipeline.inflight.ar > 0 || get_state != DONE || put_state != FREE) {
        return UCS_ERR_NO_RESOURCE;
    }
    hc->pipeline.inflight.ar++;
    hc->pipeline.stage[ar_idx].ar.state = IN_PROGRESS;
    hc->pipeline.idx.ar = (ar_idx + 1) % hc->pipeline.num_buffers;

    size_t count = hc->pipeline.stage[ar_idx].get.count;

    DPU_LOG("Issue AR idx %d count %lu total issued %zu\n",
            ar_idx, count, hc->pipeline.count_red.issued);
    assert(count > 0);
    assert(hc->pipeline.stage[ar_idx].get.ucp_req == NULL);
    assert(hc->pipeline.stage[ar_idx].put.ucp_req == NULL);

    hc->pipeline.count_red.issued += count;
    hc->pipeline.stage[ar_idx].ar.count = count;
    __sync_synchronize();
    dpu_signal_comp_threads(ctx, thread_sub_sync);
    return UCS_OK;
}

ucc_status_t dpu_check_comp_status(thread_ctx_t *ctx, thread_sync_t *sync)
{
    int i;
    for (i = 0; i < ctx->nthreads; i++) {
        if (!sync[i].done) {
            return UCC_INPROGRESS;
        }
    }
    return UCS_OK;
}

void empty(void* request, ucs_status_t status) {}

ucs_status_t dpu_hc_progress(dpu_hc_t *hc,
                    dpu_put_sync_t *sync,
                    thread_ctx_t *ctx)
{
    int i;
    ucc_status_t status;
    dpu_pipeline_stage_state_t state;
    ucs_status_ptr_t *request;

    request = ucp_worker_flush_nb(hc->ucp_worker, 0, empty);
    _dpu_request_wait(hc->ucp_worker, request);

    ucp_worker_progress(hc->ucp_worker);

    for (i=0; i<hc->pipeline.num_buffers; i++) {
        /* Get progress */
        state = hc->pipeline.stage[i].get.state;
        if (state == IN_PROGRESS) {
            request = hc->pipeline.stage[i].get.ucp_req;
            if (_dpu_req_test(request) == UCS_OK) {
                if (request != NULL ) {
                    ucp_request_free(request);
                    hc->pipeline.stage[i].get.ucp_req = NULL;
                }
                __sync_synchronize();
                hc->pipeline.stage[i].get.state = DONE;
                hc->pipeline.count_get.done += hc->pipeline.stage[i].get.count;
                hc->pipeline.inflight.get--;
                __sync_synchronize();

                DPU_LOG("Finished Get idx %d count %lu done %zu\n",
                        i, hc->pipeline.stage[i].get.count, hc->pipeline.count_get.done);
            }
        }

        /* Allreduce progress */
        state = hc->pipeline.stage[i].ar.state;
        if (state == IN_PROGRESS) {
            if (dpu_check_comp_status(ctx, thread_sub_sync) == UCS_OK) {
                
                __sync_synchronize();
                hc->pipeline.stage[i].ar.state = DONE;
                hc->pipeline.stage[i].get.state = FREE;
                hc->pipeline.count_red.done += hc->pipeline.stage[i].ar.count;
                hc->pipeline.inflight.ar--;
                __sync_synchronize();

                DPU_LOG("Finished AR idx %d count %lu done %zu\n",
                        i, hc->pipeline.stage[i].ar.count, hc->pipeline.count_red.done);
            }
        }

        /* Put progress */
        state = hc->pipeline.stage[i].put.state;
        if (state == IN_PROGRESS) {
            request = hc->pipeline.stage[i].put.ucp_req;
            if (_dpu_req_test(request) == UCS_OK) {
                if (request != NULL) {
                    ucp_request_free(request);
                    hc->pipeline.stage[i].put.ucp_req = NULL;
                }
                    
                __sync_synchronize();
                hc->pipeline.count_put.done += hc->pipeline.stage[i].put.count;
                hc->pipeline.inflight.put--;
                
                hc->pipeline.stage[i].ar.count  = 0;
                hc->pipeline.stage[i].put.count = 0;
                hc->pipeline.stage[i].ar.state  = FREE;
                hc->pipeline.stage[i].put.state = FREE;
                __sync_synchronize();

                DPU_LOG("Finished Put idx %d count %lu done %zu\n",
                        i, hc->pipeline.stage[i].put.count, hc->pipeline.count_put.done);
            }
        }
    }
    return UCS_OK;
}

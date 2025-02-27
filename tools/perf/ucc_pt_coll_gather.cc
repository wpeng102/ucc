#include "ucc_pt_coll.h"
#include "ucc_perftest.h"
#include <ucc/api/ucc.h>
#include <utils/ucc_math.h>
#include <utils/ucc_coll_utils.h>

ucc_pt_coll_gather::ucc_pt_coll_gather(ucc_datatype_t dt,
                         ucc_memory_type mt, bool is_inplace,
                         ucc_pt_comm *communicator) : ucc_pt_coll(communicator)
{
    has_inplace_   = true;
    has_reduction_ = false;
    has_range_     = true;
    has_bw_        = true;

    coll_args.mask              = 0;
    coll_args.root              = 0;
    coll_args.coll_type         = UCC_COLL_TYPE_GATHER;
    coll_args.src.info.datatype = dt;
    coll_args.src.info.mem_type = mt;
    coll_args.dst.info.datatype = dt;
    coll_args.dst.info.mem_type = mt;
    if (is_inplace) {
        coll_args.mask  = UCC_COLL_ARGS_FIELD_FLAGS;
        coll_args.flags = UCC_COLL_ARGS_FLAG_IN_PLACE;
    }
}

ucc_status_t ucc_pt_coll_gather::init_coll_args(size_t single_rank_count,
                                                   ucc_coll_args_t &args)
{
    size_t dt_size  = ucc_dt_size(coll_args.src.info.datatype);
    size_t size_src = single_rank_count * dt_size;
    size_t size_dst = comm->get_size() * single_rank_count * dt_size;
    ucc_status_t st_src, st_dst;
    bool is_root;

    args                = coll_args;
    args.dst.info.count = single_rank_count * comm->get_size();
    args.src.info.count = single_rank_count;
    is_root = (comm->get_rank() == args.root);
    if (is_root) {
        UCCCHECK_GOTO(ucc_mc_alloc(&dst_header, size_dst, args.dst.info.mem_type),
                      exit, st_dst);
        args.dst.info.buffer = dst_header->addr;
    }

    if (!is_root || !UCC_IS_INPLACE(args)) {
        UCCCHECK_GOTO(
            ucc_mc_alloc(&src_header, size_src, args.src.info.mem_type),
            free_dst, st_src);
        args.src.info.buffer = src_header->addr;
    }
    return UCC_OK;
free_dst:
    if (is_root && st_dst == UCC_OK) {
        ucc_mc_free(dst_header);
    }
    return st_src;
exit:
    return st_dst;
}

float ucc_pt_coll_gather::get_bw(float time_ms, int grsize,
                                    ucc_coll_args_t args)
{
    float S = args.src.info.count * ucc_dt_size(args.src.info.datatype);
    float N = grsize - 1;

    return (S * N) / time_ms / 1000.0;
}

void ucc_pt_coll_gather::free_coll_args(ucc_coll_args_t &args)
{
    bool is_root = (comm->get_rank() == args.root);
    if (!is_root || !UCC_IS_INPLACE(args)) {
        ucc_mc_free(src_header);
    }
    if (is_root) {
        ucc_mc_free(dst_header);
    }
}

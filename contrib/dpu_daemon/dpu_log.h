/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef DPU_LOG_H_
#define DPU_LOG_H_

#include "ucc/api/ucc.h"

static inline const char* ucc_coll_type_str(ucc_coll_type_t ct)
{
    switch(ct) {
    case UCC_COLL_TYPE_BARRIER:
        return "Barrier";
    case UCC_COLL_TYPE_BCAST:
        return "Bcast";
    case UCC_COLL_TYPE_ALLREDUCE:
        return "Allreduce";
    case UCC_COLL_TYPE_REDUCE:
        return "Reduce";
    case UCC_COLL_TYPE_ALLTOALL:
        return "Alltoall";
    case UCC_COLL_TYPE_ALLTOALLV:
        return "Alltoallv";
    case UCC_COLL_TYPE_ALLGATHER:
        return "Allgather";
    case UCC_COLL_TYPE_ALLGATHERV:
        return "Allgatherv";
    case UCC_COLL_TYPE_GATHER:
        return "Gather";
    case UCC_COLL_TYPE_GATHERV:
        return "Gatherv";
    case UCC_COLL_TYPE_SCATTER:
        return "Scatter";
    case UCC_COLL_TYPE_SCATTERV:
        return "Scatterv";
    case UCC_COLL_TYPE_FANIN:
        return "Fanin";
    case UCC_COLL_TYPE_FANOUT:
        return "Fanout";
    case UCC_COLL_TYPE_REDUCE_SCATTER:
        return "Reduce_scatter";
    case UCC_COLL_TYPE_REDUCE_SCATTERV:
        return "Reduce_scatterv";
    default:
        break;
    }
    return 0;
}

static inline const char* ucc_datatype_str(ucc_datatype_t dt)
{
    switch (dt) {
    case UCC_DT_INT8:
        return "int8";
    case UCC_DT_UINT8:
        return "uint8";
    case UCC_DT_INT16:
        return "int16";
    case UCC_DT_UINT16:
        return "uint16";
    case UCC_DT_FLOAT16:
        return "float16";
    case UCC_DT_BFLOAT16:
        return "bfloat16";
    case UCC_DT_INT32:
        return "int32";
    case UCC_DT_UINT32:
        return "uint32";
    case UCC_DT_FLOAT32:
        return "float32";
    case UCC_DT_INT64:
        return "int64";
    case UCC_DT_UINT64:
        return "uint64";
    case UCC_DT_FLOAT64:
        return "float64";
    case UCC_DT_INT128:
        return "int128";
    case UCC_DT_UINT128:
        return "uint128";
    default:
        return "userdefined";
    }
}

static inline const char* ucc_reduction_op_str(ucc_reduction_op_t op)
{
    switch(op) {
    case UCC_OP_SUM:
        return "sum";
    case UCC_OP_PROD:
        return "prod";
    case UCC_OP_MAX:
        return "max";
    case UCC_OP_MIN:
        return "min";
    case UCC_OP_LAND:
        return "land";
    case UCC_OP_LOR:
        return "lor";
    case UCC_OP_LXOR:
        return "lxor";
    case UCC_OP_BAND:
        return "band";
    case UCC_OP_BOR:
        return "bor";
    case UCC_OP_BXOR:
        return "bxor";
    case UCC_OP_MAXLOC:
        return "maxloc";
    case UCC_OP_MINLOC:
        return "minloc";
    case UCC_OP_AVG:
        return "avg";
    default:
        return NULL;
    }
}

#endif
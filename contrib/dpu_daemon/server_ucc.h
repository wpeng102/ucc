/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef TEST_MPI_H
#define TEST_MPI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mpi.h>

#include <ucc/api/ucc.h>

#define STR(x) #x

#define UCS_CHECK(_call) if (UCS_OK != (_call)) {              \
        fprintf(stderr, "*** UCS TEST FAIL: %s\n", STR(_call)); \
        MPI_Abort(MPI_COMM_WORLD, -1);                           \
    }

#define UCC_CHECK(_call) if (UCC_OK != (_call)) {              \
        fprintf(stderr, "*** UCC TEST FAIL: %s\n", STR(_call)); \
        MPI_Abort(MPI_COMM_WORLD, -1);                           \
    }

#define UCCCHECK_GOTO(_call, _label, _status)                                  \
    do {                                                                       \
        _status = (_call);                                                     \
        if (UCC_OK != _status) {                                               \
            fprintf(stderr, "UCC DPU DAEMON error: %s\n", STR(_call));         \
            goto _label;                                                       \
        }                                                                      \
    } while (0)


#define DPU_MIN(a,b) (((a)<(b))?(a):(b))
#define DPU_MAX(a,b) (((a)>(b))?(a):(b))


#define DPU_TEAM_POOL_SIZE 2048

struct dpu_hc_t;

typedef struct {
    ucc_team_h          ucc_world_team;
    ucc_lib_h           lib;
    ucc_lib_config_h    lib_config;
    int rank;
    int size;
    struct dpu_hc_t *hc;
} dpu_ucc_global_t;

typedef struct {
    dpu_ucc_global_t *g;
    ucc_context_h ctx;
    ucc_team_h team; /* this team always is dpu comm world team */
    ucc_team_h team_pool[DPU_TEAM_POOL_SIZE];
    ucc_rank_t * dpu_team_ctx_ranks[DPU_TEAM_POOL_SIZE]; /* array of lists that
                                                        maps dpu world rank to team
                                                        ranks */
    ucc_rank_t * host_team_ctx_ranks[DPU_TEAM_POOL_SIZE]; /* array of lists that
                                                        maps host world rank to team
                                                        ranks */
} dpu_ucc_comm_t;

int dpu_ucc_init(int argc, char **argv, dpu_ucc_global_t *g);
int dpu_ucc_alloc_team(dpu_ucc_global_t *g, dpu_ucc_comm_t *team);
int dpu_ucc_free_team(dpu_ucc_global_t *g, dpu_ucc_comm_t *ctx);
void dpu_ucc_finalize(dpu_ucc_global_t *g);
void dpu_ucc_progress(dpu_ucc_comm_t *team);

#endif

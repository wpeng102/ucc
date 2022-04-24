#!/bin/bash

NP=2
NT=4

hostfile="$PWD/hostfile.dpu"
WORK_DIR="/global/scratch/users/dpu/deploy"
MPI_DIR="$WORK_DIR/build-arm/ompi"
UCC_DIR="$WORK_DIR/build-arm/ucc"
DPU_BIN_DIR="$WORK_DIR/ucc/contrib/dpu_daemon"

cmd="$MPI_DIR/bin/mpirun --np ${NP} \
    --map-by ppr:1:node \
    --mca pml ucx \
    --mca btl '^openib,vader' \
    --output tag \
    --hostfile ${hostfile} \
    -x UCX_NET_DEVICES=mlx5_0:1 \
    -x UCX_TLS=rc_x \
    -x UCC_CL_BASIC_TLS=ucp \
    -x UCC_MC_CPU_REDUCE_NUM_THREADS=${NT} \
    -x UCC_TL_DPU_BCAST_WINDOW=8 \
    ${DPU_BIN_DIR}/dpu_server 1"

echo $cmd
eval "$cmd"


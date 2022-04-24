#!/bin/bash

NPROCS=2
PPN=1
BSZ=$((1 * 1024 * 1024))
ESZ=$((128 * 1024 * 1024))
MEMSZ=$((16 * 1024 * 1024 * 1024))
hostfile="$PWD/hostfile.cpu"

WORK_DIR="/global/scratch/users/dpu/deploy"
MPI_DIR="$WORK_DIR/build-x86/ompi"
OMB_DIR="$WORK_DIR/build-x86/omb"
OMB_EXE="$OMB_DIR/libexec/osu-micro-benchmarks/mpi/collective/osu_allreduce"
OMB_OPT="-i 100 -x 20 -m $BSZ:$ESZ -M $MEMSZ"

mcaopts="--mca pml ucx --mca btl '^openib,vader' "
mcaopts+="--mca opal_common_ucx_opal_mem_hooks 1 "
mcaopts+="--mca coll_ucc_enable 1 --mca coll_ucc_priority 100 --mca coll_ucc_verbose 0  "
uccopts="-x UCC_TL_DPU_TUNE=0-64K:0 "
uccopts+="-x UCC_LOG_LEVEL=warn -x UCC_CL_BASIC_TLS=ucp,dpu "
uccopts+="-x UCC_TL_DPU_PIPELINE_BLOCK_SIZE=$((4*256*1024)) "
uccopts+="-x UCC_TL_DPU_HOST_DPU_LIST=host_to_dpu.list "
uccopts+="-x UCX_NET_DEVICES=mlx5_0:1 -x UCX_TLS=rc_x "

cmd="${MPI_DIR}/bin/mpirun -np ${NPROCS} \
    --map-by ppr:$PPN:node \
    --hostfile ${hostfile} \
    ${mcaopts} ${uccopts} \
    ${OMB_EXE} ${OMB_OPT}"

echo $cmd
eval "$cmd"

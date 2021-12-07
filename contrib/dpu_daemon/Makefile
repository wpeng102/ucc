#
# Copyright (c) 2020 Mellanox Technologies.  All rights reserved.
# $COPYRIGHT$
#
# Additional copyrights may follow
#
# $HEADER$
#

UCX_DIR=$(WORK_DIR)/build-arm/ucx
UCC_DIR=$(WORK_DIR)/build-arm/ucc
MPI_DIR=$(WORK_DIR)/build-arm/ompi
MPICC=$(MPI_DIR)/bin/mpicc

CFLAGS = -I$(UCC_DIR)/include -I$(UCX_DIR)/include
LDFLAGS = -L$(UCC_DIR)/lib $(UCC_DIR)/lib/libucc.so $(UCX_DIR)/lib/libucs.so $(UCX_DIR)/lib/libucp.so -Wl,-rpath -Wl,$(UCC_DIR)/lib -Wl,-rpath -Wl,$(UCX_DIR)/lib

all:
	$(MPICC) -O3 -DNDEBUG -std=c11 $(CFLAGS) -o dpu_server dpu_server.c host_channel.c server_ucc.c $(LDFLAGS)

clean:
	rm -f dpu_server

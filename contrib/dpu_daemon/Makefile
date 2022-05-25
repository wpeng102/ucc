#
# Copyright (c) 2020 Mellanox Technologies.  All rights reserved.
# $COPYRIGHT$
#
# Additional copyrights may follow
#
# $HEADER$
#


UCX_DIR=$(BUILD_DIR)/ucx
UCC_DIR=$(BUILD_DIR)/ucc
CC=gcc

CFLAGS = -I$(UCC_DIR)/include -I$(UCX_DIR)/include -fopenmp
LDFLAGS = -L$(UCC_DIR)/lib $(UCC_DIR)/lib/libucc.so $(UCX_DIR)/lib/libucs.so $(UCX_DIR)/lib/libucp.so -Wl,-rpath -Wl,$(UCC_DIR)/lib -Wl,-rpath -Wl,$(UCX_DIR)/lib -lpthread

rel:
	$(CC) -O3 -DNDEBUG -std=c11 $(CFLAGS) -o dpu_server dpu_server.c host_channel.c server_ucc.c $(LDFLAGS)
	$(CC) -O3 -DNDEBUG -std=c11 $(CFLAGS) -o dpu_master dpu_master.c $(LDFLAGS)

dbg:
	$(CC) -O0 -g -std=c11 $(CFLAGS) -o dpu_server dpu_server.c host_channel.c server_ucc.c $(LDFLAGS)
	$(CC) -O0 -g -std=c11 $(CFLAGS) -o dpu_master dpu_master.c $(LDFLAGS)

clean:
	rm -f dpu_server dpu_master

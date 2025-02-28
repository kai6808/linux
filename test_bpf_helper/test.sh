#!/bin/bash
set -e

# Define kernel source directory
KERNEL_SRC="/users/kaishen/linux"

# compile bpf program with proper include paths
clang -target bpf -O2 -Wall \
  -I${KERNEL_SRC}/include \
  -I${KERNEL_SRC}/include/uapi \
  -I${KERNEL_SRC}/arch/x86/include \
  -I${KERNEL_SRC}/arch/x86/include/uapi \
  -I${KERNEL_SRC}/arch/x86/include/generated/uapi \
  -I${KERNEL_SRC}/include/generated/uapi \
  -c test_bpf.c -o test_bpf.o

# create and pin bpf map (need to be created before user program access)
sudo bpftool map create /sys/fs/bpf/pfn_map type array key 4 value 8 entries 1 name pfn_map

# load bpf program
sudo bpftool prog load test_bpf.o /sys/fs/bpf/test_pfn \
    map name pfn_map pinned /sys/fs/bpf/pfn_map

# run user program (automatically write pfn to map and trigger bpf)
gcc test_user.c -o test_user -lbpf

sudo ./test_user

# verify result
sudo ./verify.sh
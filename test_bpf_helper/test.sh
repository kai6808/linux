#!/bin/bash
set -e

# Directory for BPF filesystem
BPF_FS="/sys/fs/bpf"

# Ensure BPF filesystem is mounted
if ! mount | grep -q "bpf on $BPF_FS type bpf"; then
    echo "Mounting BPF filesystem..."
    sudo mount -t bpf bpf $BPF_FS
fi

# Compile BPF program using the standard userspace headers
echo "Compiling BPF program..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -I/usr/include/bpf \
    -I/usr/include \
    -c test_bpf.c -o test_bpf.o

# Create and pin the map
echo "Creating map..."
sudo bpftool map create $BPF_FS/pfn_map type array key 4 value 8 entries 1 name pfn_map

# Load the BPF program
echo "Loading BPF program..."
sudo bpftool prog load test_bpf.o $BPF_FS/test_pfn \
    map name pfn_map pinned $BPF_FS/pfn_map

# Compile and run user program
echo "Compiling user program..."
gcc -Wall -O2 test_user.c -o test_user -lbpf

echo "Running user program..."
sudo ./test_user

# Verify result
echo "Verifying result..."
sudo ./verify.sh
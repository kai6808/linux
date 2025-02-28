#!/bin/bash
set -e

# Directory for BPF filesystem
BPF_FS="/sys/fs/bpf"

# Ensure BPF filesystem is mounted
if ! mount | grep -q "bpf on $BPF_FS type bpf"; then
    echo "Mounting BPF filesystem..."
    sudo mount -t bpf bpf $BPF_FS
fi

# Simplify the BPF program to avoid kernel header issues
echo "Creating simplified BPF program..."
cat > simple_bpf.c << 'EOF'
// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define the helper function prototype
static long (*bpf_move_pfn_to_inactive_tail)(unsigned long pfn) = (void *) 212; // actual helper ID is 212

// shared bpf map (user program writes pfn)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} pfn_map SEC(".maps");

SEC("kprobe/__x64_sys_nanosleep")
int bpf_prog(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *pfn = bpf_map_lookup_elem(&pfn_map, &key);
    if (!pfn) {
        return 0;
    }

    // call helper to move page
    int ret = bpf_move_pfn_to_inactive_tail(*pfn);
    bpf_printk("Moved PFN %llu, ret=%d\n", *pfn, ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
EOF

# Compile BPF program using libbpf headers
echo "Compiling BPF program..."
clang -O2 -g -target bpf \
    -I/usr/include/bpf \
    -c simple_bpf.c -o test_bpf.o

# Create and pin the map
echo "Creating map..."
sudo rm -f $BPF_FS/pfn_map
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
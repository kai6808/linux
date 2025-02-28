#!/bin/bash
set -e

# check the result in kernel log
echo "=== Kernel Log ==="
sudo dmesg | grep "Moved PFN"

# check the pfn in lru
PFN=$(sudo bpftool map dump pinned /sys/fs/bpf/pfn_map | grep 'value' | awk '{print $NF}')
echo "=== Checking PFN $PFN in LRU ==="

# check the page status in /proc/kpageflags
KFLAGS=$(sudo cat /proc/kpageflags | awk -v pfn="$PFN" '$1 == pfn {print $2}')
if [[ $KFLAGS == *"LRU_INACTIVE_ANON"* ]]; then
    echo "Success: PFN $PFN is in Inactive LRU."
elif [[ $KFLAGS == *"LRU_ACTIVE_ANON"* ]]; then
    echo "Error: PFN $PFN is still in Active LRU."
else
    echo "Error: Unable to determine PFN $PFN status."
fi
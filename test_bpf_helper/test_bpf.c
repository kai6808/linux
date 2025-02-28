#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

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
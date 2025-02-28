#include <linux/bpf.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>

// shared bpf map (user program writes pfn)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} pfn_map SEC(".maps");

SEC("kprobe/__x64_sys_nanosleep")
int bpf_prog(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *pfn = bpf_map_lookup_elem(&pfn_map, &key);
    if (!pfn) {
        return 0;
    }

    // call helper to move page
    int ret = bpf_move_pfn_to_inactive_tail(*pfn);
    bpf_printk("Moved PFN %llu, ret=%d\n", *pfn, ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <stdint.h>  // For uint64_t

// define shared bpf map (need to be the same as the map in bpf program)
#define MAP_PATH "/sys/fs/bpf/pfn_map"

// Function to get the Page Frame Number (PFN) for a virtual address
unsigned long get_pfn(void *addr) {
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        perror("open pagemap");
        exit(1);
    }
    
    // Calculate the index in the pagemap file
    unsigned long offset = ((unsigned long)addr / getpagesize()) * sizeof(uint64_t);
    
    // Seek to the right position and read the entry
    if (lseek(pagemap_fd, offset, SEEK_SET) != offset) {
        perror("lseek");
        close(pagemap_fd);
        exit(1);
    }
    
    uint64_t entry;
    if (read(pagemap_fd, &entry, sizeof(entry)) != sizeof(entry)) {
        perror("read");
        close(pagemap_fd);
        exit(1);
    }
    
    close(pagemap_fd);
    
    // Check if the page is present
    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        exit(1);
    }
    
    // Extract the PFN (bits 0-54)
    return entry & ((1ULL << 55) - 1);
}

int main() {
    // allocate 4KB memory
    void *addr = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // write data to force page allocation
    *(volatile char *)addr = 0;

    // get pfn
    unsigned long pfn = get_pfn(addr);
    printf("Allocated page at VA: %p, PFN: %lu\n", addr, pfn);

    // open shared bpf map
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    // write pfn to map
    u32 key = 0;
    u64 value = pfn;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    // trigger bpf program (through syscall or signal)
    printf("Triggering BPF program...\n");
    syscall(SYS_nanosleep, 0, 0);  // trigger kprobe/__x64_sys_nanosleep

    // wait for result verification
    sleep(2);

    // clean up
    close(map_fd);
    munmap(addr, getpagesize());
    return 0;
}
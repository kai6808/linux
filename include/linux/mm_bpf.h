#ifndef _LINUX_MM_BPF_H
#define _LINUX_MM_BPF_H

#include <linux/errno.h>
struct bpf_prog;

#ifdef CONFIG_BPF
int bpf_lru_prog_attach(struct bpf_prog *prog);
void bpf_lru_prog_detach(void);

extern const struct bpf_prog_ops lru_reclaim_prog_ops;
#else
static inline int bpf_lru_prog_attach(struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}
static inline void bpf_lru_prog_detach(void)
{
}
#endif /* CONFIG_BPF */

#endif /* _LINUX_MM_BPF_H */
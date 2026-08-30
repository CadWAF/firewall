#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#define NULL ((void *)0)
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))

#define SEC(NAME) __attribute__((section(NAME), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				  unsigned long long flags) = (void *)BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long long (*bpf_trace_printk)(const char *fmt, unsigned int fmt_size, ...) =
	(void *)BPF_FUNC_trace_printk;
static long long (*bpf_get_socket_uid)(struct __sk_buff *skb) =
	(void *)BPF_FUNC_get_socket_uid;
static long (*bpf_skb_load_bytes)(struct __sk_buff *skb, __u32 offset, void *to,
				  __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

struct xdp_md {
	unsigned int data;
	unsigned int data_end;
	unsigned int data_meta;
	unsigned int ingress_ifindex;
	unsigned int rx_queue_index;
	unsigned int egress_ifindex;
};

#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3

#endif

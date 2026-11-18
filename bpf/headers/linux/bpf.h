#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
};

#define BPF_F_NO_PREALLOC (1U << 0)

/* Flags for bpf_map_update_elem. */
#define BPF_ANY     0 /* create or overwrite */
#define BPF_NOEXIST 1 /* create only; fails if the key already exists */
#define BPF_EXIST   2 /* overwrite only */

/* Stable BPF helper IDs (linux/bpf.h). */
enum bpf_func_id {
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_socket_uid = 47,
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

#endif

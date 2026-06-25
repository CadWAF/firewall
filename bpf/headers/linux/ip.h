#ifndef _LINUX_IP_H
#define _LINUX_IP_H

#include <linux/bpf.h>

struct iphdr {
	__u8 ihl:4;
	__u8 version:4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
};

#endif

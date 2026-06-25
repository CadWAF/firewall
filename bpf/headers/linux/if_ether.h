#ifndef _LINUX_IF_ETHER_H
#define _LINUX_IF_ETHER_H

#include <linux/bpf.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	unsigned short h_proto;
} __attribute__((packed));

#endif

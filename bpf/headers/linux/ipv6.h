#ifndef _LINUX_IPV6_H
#define _LINUX_IPV6_H

struct in6_addr {
	__u8 s6_addr[16];
};

struct ipv6hdr {
	__u8 priority:4;
	__u8 version:4;
	__u8 flow_lbl[3];
	__u16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

#endif

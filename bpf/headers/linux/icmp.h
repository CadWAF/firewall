#ifndef _LINUX_ICMP_H
#define _LINUX_ICMP_H

struct icmphdr {
	__u8 type;
	__u8 code;
	__u16 checksum;
};

#endif

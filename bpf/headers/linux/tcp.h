#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

struct tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u16 res1:4;
	__u16 doff:4;
	__u16 fin:1;
	__u16 syn:1;
	__u16 rst:1;
	__u16 psh:1;
	__u16 ack:1;
	__u16 urg:1;
	__u16 ece:1;
	__u16 cwr:1;
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
};

#endif

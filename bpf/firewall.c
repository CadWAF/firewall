#include "firewall.h"

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

static __always_inline int tcp_has_ack_ptr(void *l4, void *data_end)
{
	if ((void *)l4 + 14 > data_end)
		return 1;
	__u8 fl = *(__u8 *)(l4 + 13);
	return fl & TCP_FLAG_ACK;
}

static __always_inline int parse_l4(void *data, void *data_end, __u8 proto,
				    __u16 *src_port, __u16 *dst_port)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = data;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		*src_port = bpf_ntohs(tcp->source);
		*dst_port = bpf_ntohs(tcp->dest);
		return 0;
	}
	if (proto == IPPROTO_UDP) {
		struct udphdr *udp = data;
		if ((void *)(udp + 1) > data_end)
			return -1;
		*src_port = bpf_ntohs(udp->source);
		*dst_port = bpf_ntohs(udp->dest);
		return 0;
	}
	if (proto == IPPROTO_ICMP) {
		struct icmphdr *icmp = data;
		if ((void *)(icmp + 1) > data_end)
			return -1;
		*src_port = 0;
		*dst_port = icmp->type;
		return 0;
	}
	*src_port = 0;
	*dst_port = 0;
	return 0;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__u16 h_proto = bpf_ntohs(eth->h_proto);
	void *l3 = eth + 1;

	__u8 ip_version = 0;
	__u8 proto = 0;
	__u32 src_v4 = 0, dst_v4 = 0;
	__u8 src_v6[16] = {}, dst_v6[16] = {};
	__u16 src_port = 0, dst_port = 0;
	void *l4_ptr = 0;

	if (h_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		ip_version = 4;
		proto = ip->protocol;
		src_v4 = ip->saddr;
		dst_v4 = ip->daddr;
		l4_ptr = (void *)ip + ip->ihl * 4;
		if (parse_l4(l4_ptr, data_end, proto, &src_port, &dst_port) < 0)
			return XDP_PASS;
	} else if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		ip_version = 6;
		proto = ip6->nexthdr;
		__builtin_memcpy(src_v6, &ip6->saddr, 16);
		__builtin_memcpy(dst_v6, &ip6->daddr, 16);
		l4_ptr = (void *)ip6 + sizeof(*ip6);
		if (parse_l4(l4_ptr, data_end, proto, &src_port, &dst_port) < 0)
			return XDP_PASS;
	} else {
		return XDP_PASS;
	}

	/*
	 * DHCP lease renewal reply (server:67 -> client:68) must never be
	 * policy-gated. There is no conntrack here, so unlike an established
	 * TCP ACK, a DHCPACK/DHCPOFFER looks exactly like any other
	 * unsolicited inbound UDP packet and falls to the default drop
	 * unless the operator happened to whitelist the DHCP server IP or
	 * put port 67 in udp_in — neither of which anyone does. If it gets
	 * dropped, the DHCP client never sees the reply, keeps retrying
	 * until the lease's hard expiry, then tears down the host's own
	 * address/default route. From outside that is indistinguishable
	 * from "the firewall dropped everything", and it does not self-heal
	 * (a new DISCOVER's OFFER gets dropped too) — this is the exact
	 * failure this project's own diagnostic logging was built to catch
	 * ("firewalld.env.example: troubleshooting 24h outages"): the DHCP
	 * lease timer, not anything in the reload/refresh path.
	 */
	if (ip_version == 4 && proto == IPPROTO_UDP && src_port == 67 && dst_port == 68) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}

	/*
	 * DNS reply (resolver:53 -> our ephemeral port). Same shape of bug as
	 * the DHCP case above: the query leaves fine under udp_out, but with no
	 * conntrack the reply is just unsolicited inbound UDP, so it is dropped
	 * unless the operator thought to list 53 in udp_in. The symptom is not
	 * "the firewall blocked DNS" — it is every outbound name lookup on the
	 * host timing out, which reads as a broken network (docker builds,
	 * package installs, ACME, and webhook calls all fail at once).
	 *
	 * Restricted to replies landing on an ephemeral port: a resolver's
	 * answer always does, while a service listening below 1024 must still
	 * be opened explicitly via udp_in. That is strictly tighter than the
	 * udp_in=53 workaround it replaces, which allowed any destination port.
	 */
	if (proto == IPPROTO_UDP && src_port == 53 && dst_port >= 1024) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}

	__u32 policy_key = 0;
	struct policy_config *pol = bpf_map_lookup_elem(&policy, &policy_key);

	if (pol && pol->allow_localhost) {
		if (ip_version == 4 && (ip4_is_loopback(src_v4) ||
					ip4_is_loopback(dst_v4))) {
			bump_stats(&xdp_stats, 1);
			return XDP_PASS;
		}
	}

	/* Never blackhole Docker / compose mesh if XDP was mis-attached to a bridge. */
	if (ip_version == 4 && ip4_is_private(src_v4) && ip4_is_private(dst_v4)) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}

	if (ip_version == 4) {
		if (ip4_in_lpm(&whitelist_v4, src_v4) ||
		    ip4_in_lpm(&whitelist_v4, dst_v4)) {
			bump_stats(&xdp_stats, 1);
			return XDP_PASS;
		}
		if (ip4_in_lpm(&blocklist_v4, src_v4) ||
		    ip4_in_lpm(&blocklist_v4, dst_v4)) {
			bump_stats(&xdp_stats, 0);
			return XDP_DROP;
		}
	} else if (ip_version == 6) {
		if (ip6_in_lpm(&whitelist_v6, src_v6) ||
		    ip6_in_lpm(&whitelist_v6, dst_v6)) {
			bump_stats(&xdp_stats, 1);
			return XDP_PASS;
		}
		if (ip6_in_lpm(&blocklist_v6, src_v6) ||
		    ip6_in_lpm(&blocklist_v6, dst_v6)) {
			bump_stats(&xdp_stats, 0);
			return XDP_DROP;
		}
	}

	__u8 fw_proto = FW_PROTO_ANY;
	if (proto == IPPROTO_TCP)
		fw_proto = FW_PROTO_TCP;
	else if (proto == IPPROTO_UDP)
		fw_proto = FW_PROTO_UDP;
	else if (proto == IPPROTO_ICMP)
		fw_proto = FW_PROTO_ICMP;

	int rule_action = eval_rules(FW_DIR_IN, fw_proto, src_port, dst_port,
				     ip_version, src_v4, dst_v4, src_v6, dst_v6, 0,
				     0);
	if (rule_action == FW_ACTION_PASS) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}
	if (rule_action == FW_ACTION_DROP) {
		bump_stats(&xdp_stats, 0);
		return XDP_DROP;
	}

	/* Established TCP (ACK) and UDP replies from allowed service ports. */
	if (proto == IPPROTO_TCP && l4_ptr && tcp_has_ack_ptr(l4_ptr, data_end)) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}
	if (proto == IPPROTO_UDP && port_allowed(&udp_in_ports, src_port)) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}

	if (proto == IPPROTO_TCP && port_allowed(&tcp_in_ports, dst_port)) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}
	if (proto == IPPROTO_UDP && port_allowed(&udp_in_ports, dst_port)) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}
	if (proto == IPPROTO_ICMP) {
		bump_stats(&xdp_stats, 1);
		return XDP_PASS;
	}

	bump_stats(&xdp_stats, 0);
	return XDP_DROP;
}

static __always_inline int tc_parse_l4(struct __sk_buff *skb, __u32 off, __u8 proto,
				       __u16 *src_port, __u16 *dst_port)
{
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 ports[2];

		if (bpf_skb_load_bytes(skb, off, ports, 4) < 0)
			return -1;
		*src_port = bpf_ntohs(ports[0]);
		*dst_port = bpf_ntohs(ports[1]);
		return 0;
	}
	if (proto == IPPROTO_ICMP) {
		__u8 icmp_type;

		if (bpf_skb_load_bytes(skb, off, &icmp_type, 1) < 0)
			return -1;
		*src_port = 0;
		*dst_port = icmp_type;
		return 0;
	}
	*src_port = 0;
	*dst_port = 0;
	return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	__u64 uid_gid = bpf_get_socket_uid(skb);
	__u32 uid = (__u32)uid_gid;
	__u32 gid = (__u32)(uid_gid >> 32);

	struct ethhdr eth;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;

	__u16 h_proto = bpf_ntohs(eth.h_proto);
	__u32 l3_off = sizeof(eth);

	__u8 ip_version = 0;
	__u8 proto = 0;
	__u32 src_v4 = 0, dst_v4 = 0;
	__u8 src_v6[16] = {}, dst_v6[16] = {};
	__u16 src_port = 0, dst_port = 0;
	__u32 l4_off = 0;

	if (h_proto == ETH_P_IP) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, l3_off, &ip, sizeof(ip)) < 0)
			return TC_ACT_OK;
		__u32 ihl = ip.ihl * 4;
		if (l3_off + ihl > skb->len)
			return TC_ACT_OK;
		ip_version = 4;
		proto = ip.protocol;
		src_v4 = ip.saddr;
		dst_v4 = ip.daddr;
		l4_off = l3_off + ihl;
		if (tc_parse_l4(skb, l4_off, proto, &src_port, &dst_port) < 0)
			return TC_ACT_OK;
	} else if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, l3_off, &ip6, sizeof(ip6)) < 0)
			return TC_ACT_OK;
		if (l3_off + sizeof(ip6) > skb->len)
			return TC_ACT_OK;
		ip_version = 6;
		proto = ip6.nexthdr;
		__builtin_memcpy(src_v6, &ip6.saddr, 16);
		__builtin_memcpy(dst_v6, &ip6.daddr, 16);
		l4_off = l3_off + sizeof(ip6);
		if (tc_parse_l4(skb, l4_off, proto, &src_port, &dst_port) < 0)
			return TC_ACT_OK;
	} else {
		return TC_ACT_OK;
	}

	/* Docker hairpin: container -> host public IP (published ports). */
	if (ip_version == 4 && src_v4 == dst_v4) {
		bump_stats(&tc_stats, 1);
		return TC_ACT_OK;
	}

	/* Allow established TCP replies — only filter new outbound SYNs. */
	if (proto == IPPROTO_TCP) {
		__u8 fl = 0;

		if (bpf_skb_load_bytes(skb, l4_off + 13, &fl, 1) < 0) {
			bump_stats(&tc_stats, 1);
			return TC_ACT_OK;
		}
		if (!(fl & TCP_FLAG_SYN) || (fl & TCP_FLAG_ACK)) {
			bump_stats(&tc_stats, 1);
			return TC_ACT_OK;
		}
	}

	__u32 policy_key = 0;
	struct policy_config *pol = bpf_map_lookup_elem(&policy, &policy_key);

	if (pol && pol->allow_localhost) {
		if (ip_version == 4 && (ip4_is_loopback(src_v4) ||
					ip4_is_loopback(dst_v4))) {
			bump_stats(&tc_stats, 1);
			return TC_ACT_OK;
		}
	}

	/* Docker bridge / overlay mesh must not be shot by TC on a mis-bound iface. */
	if (ip_version == 4 && ip4_is_private(src_v4) && ip4_is_private(dst_v4)) {
		bump_stats(&tc_stats, 1);
		return TC_ACT_OK;
	}

	if (ip_version == 4) {
		if (ip4_in_lpm(&whitelist_v4, src_v4) ||
		    ip4_in_lpm(&whitelist_v4, dst_v4)) {
			bump_stats(&tc_stats, 1);
			return TC_ACT_OK;
		}
		if (ip4_in_lpm(&blocklist_v4, src_v4) ||
		    ip4_in_lpm(&blocklist_v4, dst_v4)) {
			bump_stats(&tc_stats, 0);
			return TC_ACT_SHOT;
		}
	} else if (ip_version == 6) {
		if (ip6_in_lpm(&whitelist_v6, src_v6) ||
		    ip6_in_lpm(&whitelist_v6, dst_v6)) {
			bump_stats(&tc_stats, 1);
			return TC_ACT_OK;
		}
		if (ip6_in_lpm(&blocklist_v6, src_v6) ||
		    ip6_in_lpm(&blocklist_v6, dst_v6)) {
			bump_stats(&tc_stats, 0);
			return TC_ACT_SHOT;
		}
	}

	__u8 fw_proto = FW_PROTO_ANY;
	if (proto == IPPROTO_TCP)
		fw_proto = FW_PROTO_TCP;
	else if (proto == IPPROTO_UDP)
		fw_proto = FW_PROTO_UDP;
	else if (proto == IPPROTO_ICMP)
		fw_proto = FW_PROTO_ICMP;

	int rule_action = eval_rules(FW_DIR_OUT, fw_proto, src_port, dst_port,
				     ip_version, src_v4, dst_v4, src_v6, dst_v6, uid,
				     gid);
	if (rule_action == FW_ACTION_PASS) {
		bump_stats(&tc_stats, 1);
		return TC_ACT_OK;
	}
	if (rule_action == FW_ACTION_DROP) {
		bump_stats(&tc_stats, 0);
		return TC_ACT_SHOT;
	}

	if (proto == IPPROTO_TCP && port_allowed(&tcp_out_ports, dst_port)) {
		bump_stats(&tc_stats, 1);
		return TC_ACT_OK;
	}
	/* UDP/ICMP egress: whitelist/blocklist/rules only (no strict port list). */
	if (proto == IPPROTO_UDP || proto == IPPROTO_ICMP) {
		bump_stats(&tc_stats, 1);
		return TC_ACT_OK;
	}

	bump_stats(&tc_stats, 0);
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";

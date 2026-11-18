#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 64
#define BPF_EVAL_RULE_LIMIT 64
#define MAX_PORTS_PER_RULE 15

enum fw_proto {
	FW_PROTO_ANY = 0,
	FW_PROTO_TCP = 1,
	FW_PROTO_UDP = 2,
	FW_PROTO_ICMP = 3,
};

enum fw_direction {
	FW_DIR_IN = 1,
	FW_DIR_OUT = 2,
};

enum fw_action {
	FW_ACTION_PASS = 1,
	FW_ACTION_DROP = 2,
};

enum fw_port_spec {
	FW_PORT_NONE = 0,
	FW_PORT_SRC = 1,
	FW_PORT_DST = 2,
};

enum fw_ip_spec {
	FW_IP_NONE = 0,
	FW_IP_SRC = 1,
	FW_IP_DST = 2,
};

enum fw_uid_gid_type {
	FW_UID_GID_NONE = 0,
	FW_UID_GID_UID = 1,
	FW_UID_GID_GID = 2,
};

struct fw_rule {
	__u8 proto;
	__u8 direction;
	__u8 action;
	__u8 port_spec;
	__u8 ip_spec;
	__u8 ip_version;
	__u8 port_count;
	__u8 uid_gid_type;
	__u8 _pad;
	__u16 ports[MAX_PORTS_PER_RULE];
	__u8 ip_prefixlen;
	__u8 _pad2[3];
	__u32 ipv4_addr;
	__u32 ipv6_addr[4];
	__u32 uid_gid;
};

struct policy_config {
	__u32 allow_localhost;
	__u32 default_drop;
};

struct lpm_key_v4 {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm_key_v6 {
	__u32 prefixlen;
	__u8 addr[16];
};

/*
 * Why a packet was refused.
 *
 * Aggregate counters answer "how much" and never "who" or "what for", which
 * is the only question worth asking after an incident. These travel with the
 * source address so userspace can say "this address, this many times, for
 * this reason".
 */
enum fw_drop_reason {
	FW_DROP_NONE = 0,
	FW_DROP_BLOCKLIST = 1,
	FW_DROP_RULE = 2,
	FW_DROP_NO_PORT = 3,
};

/* Key of one refused source. Ports are deliberately absent: a scan walks
 * thousands of them and would evict everything else from the map. */
struct drop_key {
	__u8 ip_version;
	__u8 reason;
	__u8 proto;
	__u8 _pad;
	__u32 addr_v4;
	__u8 addr_v6[16];
};

struct drop_record {
	__u64 packets;
	__u64 first_ns;
	__u64 last_ns;
	__u16 last_dst_port;
	__u16 _pad[3];
};

struct pkt_stats {
	__u64 pass;
	__u64 drop;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 10240);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
} whitelist_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 10240);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, __u8);
} whitelist_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 10240);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
} blocklist_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 10240);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, __u8);
} blocklist_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct fw_rule);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} rule_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} tcp_in_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} udp_in_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} tcp_out_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} udp_out_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_config);
} policy SEC(".maps");

/*
 * Refused sources, aggregated in kernel.
 *
 * An LRU hash rather than a ring buffer of events: a flood is millions of
 * packets a second and userspace could not drain one event per packet without
 * becoming the bottleneck it is meant to measure. Counting per source turns
 * that same flood into one entry per attacker, which is the shape the answer
 * wants anyway. LRU because the eviction policy under pressure should be
 * "forget the quietest", not "stop recording" or "grow without bound".
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct drop_key);
	__type(value, struct drop_record);
} drop_log SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pkt_stats);
} xdp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pkt_stats);
} tc_stats SEC(".maps");

static __always_inline void bump_stats(void *map, int pass)
{
	__u32 key = 0;
	struct pkt_stats *st = bpf_map_lookup_elem(map, &key);
	if (!st)
		return;
	/*
	 * Plain increments, not __sync_fetch_and_add.
	 *
	 * These are PERCPU maps: bpf_map_lookup_elem hands back this CPU's own
	 * copy, which no other CPU can reach, so there is nothing to race
	 * against. The atomic compiled to a locked read-modify-write on every
	 * single packet — bus-locking to protect a value only one CPU can
	 * touch. The read side already sums the per-CPU values.
	 */
	if (pass)
		st->pass++;
	else
		st->drop++;
}

/*
 * Records one refusal. Called from a single place in the XDP program: inlined
 * at each of the ten drop sites it would multiply both the instruction count
 * and the states the verifier has to walk, and this program has already been
 * over that ceiling once.
 */
/*
 * Packs the small scalars into one argument. A BPF-to-BPF call passes
 * arguments in registers and takes at most five; the alternative was building
 * the key in the caller, which is the part that had to move out of it.
 */
#define FW_DROP_META(ipver, reason, proto, dport)                          \
	(((__u64)(ipver)) | ((__u64)(reason) << 8) | ((__u64)(proto) << 16) \
	 | ((__u64)(dport) << 32))

/*
 * Records one refusal.
 *
 * Deliberately not inlined. Inlined at each drop exit it is verified once for
 * every state that reaches it, inflating both the instruction count and the
 * number of states the verifier must walk. As a single out-of-line call it is
 * checked once.
 */
static __noinline void record_drop(__u64 meta, __u32 src_v4, __u8 *src_v6)
{
	struct drop_key key = {};
	key.ip_version = (__u8)(meta & 0xff);
	key.reason = (__u8)((meta >> 8) & 0xff);
	key.proto = (__u8)((meta >> 16) & 0xff);

	if (key.ip_version == 4)
		key.addr_v4 = src_v4;
	else if (src_v6)
		__builtin_memcpy(key.addr_v6, src_v6, 16);

	__u16 dst_port = (__u16)((meta >> 32) & 0xffff);
	__u64 now = bpf_ktime_get_ns();

	struct drop_record *rec = bpf_map_lookup_elem(&drop_log, &key);
	if (rec) {
		rec->packets++;
		rec->last_ns = now;
		rec->last_dst_port = dst_port;
		return;
	}

	struct drop_record fresh = {
		.packets = 1,
		.first_ns = now,
		.last_ns = now,
		.last_dst_port = dst_port,
	};
	/* BPF_NOEXIST: another CPU may have inserted the same key between the
	 * lookup and here, and losing that race should cost this packet's count
	 * rather than overwrite the other CPU's record. */
	bpf_map_update_elem(&drop_log, &key, &fresh, BPF_NOEXIST);
}

/* addr is network-byte-order IPv4. */
static __always_inline int ip4_is_loopback(__u32 addr)
{
	return (bpf_ntohl(addr) & 0xff000000) == 0x7f000000; /* 127.0.0.0/8 */
}

/* RFC1918 — Docker bridge / compose networks (waf-filter). */
static __always_inline int ip4_is_private(__u32 addr)
{
	__u32 h = bpf_ntohl(addr);
	if ((h & 0xff000000) == 0x0a000000) /* 10.0.0.0/8 */
		return 1;
	if ((h & 0xfff00000) == 0xac100000) /* 172.16.0.0/12 */
		return 1;
	if ((h & 0xffff0000) == 0xc0a80000) /* 192.168.0.0/16 */
		return 1;
	return 0;
}

static __always_inline int ip4_in_lpm(void *map, __u32 addr)
{
	struct lpm_key_v4 key = {
		.prefixlen = 32,
		.addr = addr,
	};
	return bpf_map_lookup_elem(map, &key) != NULL;
}

static __always_inline int ip6_in_lpm(void *map, __u8 addr[16])
{
	struct lpm_key_v6 key = {};
	key.prefixlen = 128;
	__builtin_memcpy(key.addr, addr, 16);
	return bpf_map_lookup_elem(map, &key) != NULL;
}

static __always_inline int port_allowed(void *map, __u16 port)
{
	__u8 *v = bpf_map_lookup_elem(map, &port);
	if (!v)
		return 0;
	return *v != 0;
}

static __always_inline __u8 rule_v6_byte(__u32 rule_v6[4], int i)
{
	int w = i >> 2;
	int b = 3 - (i & 3);
	return (__u8)(rule_v6[w] >> (b * 8));
}

static __always_inline int ip6_addrs_equal(__u8 target[16], __u32 rule_v6[4])
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (target[i] != rule_v6_byte(rule_v6, i))
			return 0;
	}
	return 1;
}

static __always_inline int ip6_prefix_match(__u8 target[16], __u32 rule_v6[4],
					    __u8 prefixlen)
{
	__u32 full_bytes = prefixlen / 8;
	__u32 rem_bits = prefixlen % 8;
	__u8 mask = rem_bits ? (__u8)((0xFF << (8 - rem_bits)) & 0xFF) : 0;

	/*
	 * Fully unrolled over all 16 bytes so the index is a compile-time
	 * constant — target[i] and rule_v6[i>>2] are then constant stack
	 * offsets. full_bytes/rem_bits are runtime scalars used only in the
	 * comparisons, never as an index, so there is no variable-offset stack
	 * read for the verifier to reject.
	 */
#pragma unroll
	for (int i = 0; i < 16; i++) {
		__u8 rb = rule_v6_byte(rule_v6, i);
		if ((__u32)i < full_bytes) {
			if (target[i] != rb)
				return 0;
		} else if ((__u32)i == full_bytes && rem_bits != 0) {
			if ((target[i] & mask) != (rb & mask))
				return 0;
		}
		/* i > full_bytes: byte lies outside the prefix — ignore. */
	}
	return 1;
}

static __always_inline int match_ip_rule(struct fw_rule *rule, __u8 ip_version,
					 __u32 src_v4, __u32 dst_v4,
					 __u8 src_v6[16], __u8 dst_v6[16])
{
	if (rule->ip_spec == FW_IP_NONE)
		return 1;

	if (rule->ip_version == 4 && ip_version == 4) {
		__u32 target = rule->ip_spec == FW_IP_SRC ? src_v4 : dst_v4;
		struct lpm_key_v4 key = {
			.prefixlen = rule->ip_prefixlen ? rule->ip_prefixlen : 32,
			.addr = target,
		};
		if (rule->ip_prefixlen < 32) {
			__u32 mask = bpf_htonl(~((1U << (32 - rule->ip_prefixlen)) - 1));
			key.addr &= mask;
		}
		return rule->ipv4_addr == key.addr;
	}

	if (rule->ip_version == 6 && ip_version == 6) {
		__u8 prefixlen = rule->ip_prefixlen ? rule->ip_prefixlen : 128;
		if (rule->ip_spec == FW_IP_SRC) {
			if (prefixlen == 128)
				return ip6_addrs_equal(src_v6, rule->ipv6_addr);
			return ip6_prefix_match(src_v6, rule->ipv6_addr, prefixlen);
		}
		if (prefixlen == 128)
			return ip6_addrs_equal(dst_v6, rule->ipv6_addr);
		return ip6_prefix_match(dst_v6, rule->ipv6_addr, prefixlen);
	}

	return 0;
}

static __always_inline int match_port_rule(struct fw_rule *rule, __u16 src_port,
					   __u16 dst_port)
{
	if (rule->port_spec == FW_PORT_NONE)
		return 1;

	__u16 target = rule->port_spec == FW_PORT_SRC ? src_port : dst_port;
	/*
	 * Fixed count, fully unrolled, so i is a compile-time constant and
	 * rule->ports[i] is a constant stack offset. A data-dependent `break`
	 * would keep i a runtime value — a variable-offset stack read, which the
	 * verifier rejects now that the enclosing scan is a real bpf_loop rather
	 * than unrolled. The i < port_count guard replaces the break.
	 */
#pragma unroll
	for (int i = 0; i < MAX_PORTS_PER_RULE; i++) {
		if ((__u32)i < rule->port_count && rule->ports[i] == target)
			return 1;
	}
	return 0;
}

/*
 * bpf_loop() is BPF helper #181. It is declared here as a direct helper pointer
 * (exactly as libbpf's generated bpf_helper_defs.h does) so the program builds
 * against headers that predate the helper — e.g. the older libbpf that ships
 * with Homebrew llvm on macOS, where `bpf_loop` is otherwise undeclared. The
 * private name avoids any clash with a newer header that also provides it. The
 * helper needs kernel >= 5.17 at load time.
 */
static long (*fw_bpf_loop)(__u32 nr_loops, void *callback_fn,
			   void *callback_ctx, __u64 flags) = (void *)181;

/*
 * Per-rule scan state handed to the bpf_loop() callback. The packet's IPv6
 * addresses are copied in by value (callers pass pointers to 16-byte stack
 * buffers), so the callback reads only this stack struct and never a packet
 * pointer — which keeps it trivially verifiable.
 */
struct rule_scan_ctx {
	__u8 direction;
	__u8 proto;
	__u8 ip_version;
	__u16 src_port;
	__u16 dst_port;
	__u32 src_v4;
	__u32 dst_v4;
	__u32 uid;
	__u32 gid;
	__u8 src_v6[16];
	__u8 dst_v6[16];
	__u32 max;
	int action;   /* output: action of the first matching rule */
	__u8 matched; /* output: set once a rule matches */
};

/*
 * One iteration of the rule scan, run by bpf_loop(). Return 1 to stop (a rule
 * matched, or the index reached the active rule count), 0 to continue. The
 * verifier checks this body ONCE regardless of how many times it runs, which
 * is the whole point: a plain 64-iteration C loop over this same body — a map
 * lookup, a full rule copy, the nested port/IP matches and several branches —
 * makes the verifier walk every iteration and blows past its
 * million-instruction complexity ceiling, whether the loop is unrolled or
 * rolled (verified: v0.3.2 unrolled and v0.3.3 rolled both failed at load with
 * "Processed 1000001 insn").
 */
static long rule_scan_cb(__u32 i, void *vctx)
{
	struct rule_scan_ctx *c = vctx;
	if (i >= c->max)
		return 1;

	__u32 idx = i;
	struct fw_rule *rulep = bpf_map_lookup_elem(&rules, &idx);
	if (!rulep)
		return 0;

	struct fw_rule rule;
	__builtin_memcpy(&rule, rulep, sizeof(rule));
	if (rule.direction != c->direction)
		return 0;
	if (rule.proto != FW_PROTO_ANY && rule.proto != c->proto)
		return 0;
	if (rule.uid_gid_type == FW_UID_GID_UID && c->uid != rule.uid_gid)
		return 0;
	if (rule.uid_gid_type == FW_UID_GID_GID && c->gid != rule.uid_gid)
		return 0;
	if (!match_port_rule(&rule, c->src_port, c->dst_port))
		return 0;
	if (!match_ip_rule(&rule, c->ip_version, c->src_v4, c->dst_v4,
			   c->src_v6, c->dst_v6))
		return 0;

	c->action = rule.action;
	c->matched = 1;
	return 1;
}

/*
 * Evaluated in its own bpf-to-bpf frame rather than inlined into the XDP/TC
 * entry: inlined, the per-rule stack copy lands in the caller's frame and, on
 * the drop path, is summed with record_drop's frame past the 512-byte stack
 * ceiling. As its own call the scan's stack is counted separately and the
 * entry frame stays small. The eleven scalars are packed into three words plus
 * the two IPv6 pointers; the __always_inline wrapper below keeps the call
 * sites unchanged.
 *
 * The scan runs through bpf_loop() (kernel >= 5.17), not a C loop: this program
 * overruns the verifier's million-instruction ceiling when it has to walk a
 * 64-iteration scan over the body above, so bpf_loop() verifies that body once
 * and runs the iterations at runtime — verification cost no longer scales with
 * the rule limit.
 */
static __noinline int eval_rules_scan(__u64 meta, __u64 v4, __u64 uidgid,
				      __u8 *src_v6, __u8 *dst_v6)
{
	__u32 count_key = 0;
	__u32 *count = bpf_map_lookup_elem(&rule_count, &count_key);
	if (!count || *count == 0)
		return 0;

	__u32 max = *count;
	if (max > BPF_EVAL_RULE_LIMIT)
		max = BPF_EVAL_RULE_LIMIT;

	struct rule_scan_ctx c = {};
	c.direction = (__u8)(meta & 0xff);
	c.proto = (__u8)((meta >> 8) & 0xff);
	c.ip_version = (__u8)((meta >> 16) & 0xff);
	c.src_port = (__u16)((meta >> 24) & 0xffff);
	c.dst_port = (__u16)((meta >> 40) & 0xffff);
	c.src_v4 = (__u32)(v4 & 0xffffffff);
	c.dst_v4 = (__u32)(v4 >> 32);
	c.uid = (__u32)(uidgid & 0xffffffff);
	c.gid = (__u32)(uidgid >> 32);
	if (src_v6)
		__builtin_memcpy(c.src_v6, src_v6, 16);
	if (dst_v6)
		__builtin_memcpy(c.dst_v6, dst_v6, 16);
	c.max = max;

	/* nr_loops = max (<= 64); the callback also guards i >= max defensively. */
	fw_bpf_loop(max, rule_scan_cb, &c, 0);
	return c.matched ? c.action : 0;
}

/*
 * Thin packer so callers keep the readable eleven-argument signature. Inlined,
 * it adds only a few ALU ops to the caller; the heavy scan is the call above.
 */
static __always_inline int eval_rules(__u8 direction, __u8 proto, __u16 src_port,
				      __u16 dst_port, __u8 ip_version,
				      __u32 src_v4, __u32 dst_v4, __u8 src_v6[16],
				      __u8 dst_v6[16], __u32 uid, __u32 gid)
{
	__u64 meta = (__u64)direction | ((__u64)proto << 8) |
		     ((__u64)ip_version << 16) | ((__u64)src_port << 24) |
		     ((__u64)dst_port << 40);
	__u64 v4 = (__u64)src_v4 | ((__u64)dst_v4 << 32);
	__u64 uidgid = (__u64)uid | ((__u64)gid << 32);
	return eval_rules_scan(meta, v4, uidgid, src_v6, dst_v6);
}

#endif /* FIREWALL_H */

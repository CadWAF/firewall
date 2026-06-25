package policy

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/huzenkon/waf-firewall/internal/bpf"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/parser"
)

type State struct {
	Whitelist []string
	Blocklist []string
	Rules     []parser.Entry
	Ports     *config.PortsConfig
}

func LoadState(allowPath, denyPath, portsPath string) (*State, error) {
	allowEntries, err := parser.ParseFile(allowPath, parser.ActionPass)
	if err != nil {
		return nil, fmt.Errorf("firewall.allow: %w", err)
	}
	denyEntries, err := parser.ParseFile(denyPath, parser.ActionDrop)
	if err != nil {
		return nil, fmt.Errorf("firewall.deny: %w", err)
	}
	ports, err := config.LoadPorts(portsPath)
	if err != nil {
		return nil, fmt.Errorf("ports.conf: %w", err)
	}

	st := &State{Ports: ports}
	var rules []parser.Entry

	for _, e := range allowEntries {
		switch e.Kind {
		case parser.EntrySimpleIP:
			st.Whitelist = append(st.Whitelist, e.Raw)
		case parser.EntryComplexRule:
			rules = append(rules, e)
		}
	}
	for _, e := range denyEntries {
		switch e.Kind {
		case parser.EntrySimpleIP:
			st.Blocklist = append(st.Blocklist, e.Raw)
		case parser.EntryComplexRule:
			rules = append(rules, e)
		}
	}
	st.Rules = expandRules(rules)
	if len(st.Rules) > parser.MaxRules {
		return nil, fmt.Errorf("too many rules (%d > %d)", len(st.Rules), parser.MaxRules)
	}
	return st, nil
}

func expandRules(rules []parser.Entry) []parser.Entry {
	var out []parser.Entry
	for _, r := range rules {
		if len(r.Ports) <= parser.MaxPortsPerRule {
			out = append(out, r)
			continue
		}
		for i := 0; i < len(r.Ports); i += parser.MaxPortsPerRule {
			end := i + parser.MaxPortsPerRule
			if end > len(r.Ports) {
				end = len(r.Ports)
			}
			chunk := r
			chunk.Ports = append([]uint16(nil), r.Ports[i:end]...)
			out = append(out, chunk)
		}
	}
	return out
}

func ApplyMaps(objs *bpf.FirewallObjects, st *State) error {
	if err := clearLPMv4(objs.WhitelistV4); err != nil {
		return err
	}
	if err := clearLPMv6(objs.WhitelistV6); err != nil {
		return err
	}
	if err := clearLPMv4(objs.BlocklistV4); err != nil {
		return err
	}
	if err := clearLPMv6(objs.BlocklistV6); err != nil {
		return err
	}
	if err := clearHash(objs.TcpInPorts); err != nil {
		return err
	}
	if err := clearHash(objs.UdpInPorts); err != nil {
		return err
	}
	if err := clearHash(objs.TcpOutPorts); err != nil {
		return err
	}
	if err := clearHash(objs.UdpOutPorts); err != nil {
		return err
	}

	for _, ip := range st.Whitelist {
		if err := putLPMIP(objs.WhitelistV4, objs.WhitelistV6, ip); err != nil {
			return fmt.Errorf("whitelist %s: %w", ip, err)
		}
	}
	for _, ip := range st.Blocklist {
		if err := putLPMIP(objs.BlocklistV4, objs.BlocklistV6, ip); err != nil {
			return fmt.Errorf("blocklist %s: %w", ip, err)
		}
	}

	for _, p := range st.Ports.TCPIn {
		if err := objs.TcpInPorts.Put(p, uint8(1)); err != nil {
			return err
		}
	}
	for _, p := range st.Ports.UDPIn {
		if err := objs.UdpInPorts.Put(p, uint8(1)); err != nil {
			return err
		}
	}
	for _, p := range st.Ports.TCPOut {
		if err := objs.TcpOutPorts.Put(p, uint8(1)); err != nil {
			return err
		}
	}
	for _, p := range st.Ports.UDPOut {
		if err := objs.UdpOutPorts.Put(p, uint8(1)); err != nil {
			return err
		}
	}

	policyKey := uint32(0)
	pol := bpf.FirewallPolicyConfig{
		AllowLocalhost: boolToU32(st.Ports.AllowLocalhost),
		DefaultDrop:    1,
	}
	if err := objs.Policy.Put(policyKey, pol); err != nil {
		return err
	}

	compiled := compileRules(st.Rules)
	countKey := uint32(0)
	count := uint32(len(compiled))
	if err := objs.RuleCount.Put(countKey, count); err != nil {
		return err
	}
	for i, rule := range compiled {
		if err := objs.Rules.Put(uint32(i), rule); err != nil {
			return err
		}
	}
	return nil
}

func compileRules(entries []parser.Entry) []bpf.FirewallFwRule {
	out := make([]bpf.FirewallFwRule, 0, len(entries))
	for _, e := range entries {
		r := bpf.FirewallFwRule{
			Direction:  uint8(e.Direction),
			Action:     uint8(e.Action),
			PortSpec:   uint8(e.PortSpec),
			IpSpec:     uint8(e.IPSpec),
			PortCount:  uint8(len(e.Ports)),
			UidGidType: uint8(e.UIDGIDType),
			UidGid:     e.UIDGID,
		}
		switch e.Proto {
		case parser.ProtoTCP:
			r.Proto = 1
		case parser.ProtoUDP:
			r.Proto = 2
		case parser.ProtoICMP:
			r.Proto = 3
		}
		for i, p := range e.Ports {
			if i >= 15 {
				break
			}
			r.Ports[i] = p
		}
		if e.IPSpec != parser.IPNone && e.UIDGIDType == parser.UIDGIDNone {
			if v4 := e.IP.To4(); v4 != nil {
				r.IpVersion = 4
				r.IpPrefixlen = uint8(e.PrefixLen)
				r.Ipv4Addr = binary.BigEndian.Uint32(v4)
				if e.PrefixLen < 32 {
					mask := ^uint32((1 << (32 - e.PrefixLen)) - 1)
					r.Ipv4Addr &= mask
				}
			} else {
				r.IpVersion = 6
				r.IpPrefixlen = uint8(e.PrefixLen)
				ip16 := e.IP.To16()
				for i := 0; i < 4; i++ {
					r.Ipv6Addr[i] = binary.BigEndian.Uint32(ip16[i*4 : (i+1)*4])
				}
			}
		}
		out = append(out, r)
	}
	return out
}

func putLPMIP(v4, v6 *ebpf.Map, cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid IP %q", cidr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := bpf.FirewallLpmKeyV4{Prefixlen: 32, Addr: binary.BigEndian.Uint32(ip4)}
			return v4.Put(key, uint8(1))
		}
		key := bpf.FirewallLpmKeyV6{Prefixlen: 128}
		copy(key.Addr[:], ip.To16())
		return v6.Put(key, uint8(1))
	}
	ones, _ := network.Mask.Size()
	if v4ip := ip.To4(); v4ip != nil {
		addr := binary.BigEndian.Uint32(v4ip)
		if ones < 32 {
			mask := ^uint32((1 << (32 - ones)) - 1)
			addr &= mask
		}
		key := bpf.FirewallLpmKeyV4{Prefixlen: uint32(ones), Addr: addr}
		return v4.Put(key, uint8(1))
	}
	key := bpf.FirewallLpmKeyV6{Prefixlen: uint32(ones)}
	copy(key.Addr[:], ip.To16())
	return v6.Put(key, uint8(1))
}

func clearLPMv4(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV4
	var val uint8
	for iter.Next(&key, &val) {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}

func clearLPMv6(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV6
	var val uint8
	for iter.Next(&key, &val) {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}

func clearHash(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	iter := m.Iterate()
	var key uint16
	var val uint8
	for iter.Next(&key, &val) {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}

func boolToU32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

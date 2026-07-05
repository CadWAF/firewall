package policy

import (
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/huzenkon/waf-firewall/internal/bpf"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/parser"
	"github.com/huzenkon/waf-firewall/internal/ports"
)

// sshPort returns the SSH port from SSH_PORT env or 22.
func sshPort() uint16 {
	if v := os.Getenv("SSH_PORT"); v != "" {
		if p, err := ports.ParseList(v); err == nil && len(p) == 1 {
			return p[0]
		}
	}
	return 22
}

// ensureSSHInPortsEnabled is opt-in via FIREWALL_ENSURE_SSH_IN=true for setups that
// rely on tcp_in instead of whitelist-only SSH access.
func ensureSSHInPortsEnabled() bool {
	return os.Getenv("FIREWALL_ENSURE_SSH_IN") == "true"
}

// EnsureSafePorts optionally injects SSH/QUIC ports when enabled by env.
func EnsureSafePorts(pc *config.PortsConfig) {
	if pc == nil {
		return
	}
	if ensureSSHInPortsEnabled() {
		pc.TCPIn = ensurePort(pc.TCPIn, sshPort())
		pc.TCPOut = ensurePort(pc.TCPOut, sshPort())
	}
	if containsPort(pc.TCPIn, 443) {
		pc.UDPIn = ensurePort(pc.UDPIn, 443)
		pc.TCPOut = ensurePort(pc.TCPOut, 443)
	}
}

func ensurePort(list []uint16, p uint16) []uint16 {
	if containsPort(list, p) {
		return list
	}
	list = append(list, p)
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

func containsPort(list []uint16, p uint16) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}

// ValidateSSHReachable returns an error when tcp_in excludes SSH and no whitelist exists.
func ValidateSSHReachable(allowPath string, pc *config.PortsConfig) error {
	if containsPort(pc.TCPIn, sshPort()) {
		return nil
	}
	allowEntries, err := parser.ParseFile(allowPath, parser.ActionPass)
	if err != nil {
		return err
	}
	var whitelist []string
	for _, e := range allowEntries {
		if e.Kind == parser.EntrySimpleIP {
			whitelist = append(whitelist, e.Raw)
		}
	}
	if len(whitelist) == 0 {
		return fmt.Errorf("tcp_in has no port %d and firewall.allow is empty — refusing to lock out SSH", sshPort())
	}
	return nil
}

// lpmKeysFromCIDRs builds BPF LPM keys for all CIDRs in the list.
func lpmKeysFromCIDRs(cidrs []string) ([]bpf.FirewallLpmKeyV4, []bpf.FirewallLpmKeyV6, error) {
	var v4 []bpf.FirewallLpmKeyV4
	var v6 []bpf.FirewallLpmKeyV6
	for _, cidr := range cidrs {
		k4, k6, err := lpmKeysFromCIDR(cidr)
		if err != nil {
			return nil, nil, err
		}
		if k4 != nil {
			v4 = append(v4, *k4)
		}
		if k6 != nil {
			v6 = append(v6, *k6)
		}
	}
	return v4, v6, nil
}

func lpmKeysFromCIDR(cidr string) (*bpf.FirewallLpmKeyV4, *bpf.FirewallLpmKeyV6, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP %q", cidr)
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := bpf.FirewallLpmKeyV4{Prefixlen: 32, Addr: ip4BPFKey(ip4)}
			return &key, nil, nil
		}
		key := bpf.FirewallLpmKeyV6{Prefixlen: 128}
		copy(key.Addr[:], ip.To16())
		return nil, &key, nil
	}
	ones, _ := network.Mask.Size()
	if v4ip := ip.To4(); v4ip != nil {
		addr := ip4BPFKey(v4ip)
		if ones < 32 {
			addr &= ip4BPFMask(ones)
		}
		key := bpf.FirewallLpmKeyV4{Prefixlen: uint32(ones), Addr: addr}
		return &key, nil, nil
	}
	key := bpf.FirewallLpmKeyV6{Prefixlen: uint32(ones)}
	copy(key.Addr[:], ip.To16())
	return nil, &key, nil
}

func syncLPMv4(m *ebpf.Map, want []bpf.FirewallLpmKeyV4) error {
	if m == nil {
		return nil
	}
	desired := make(map[bpf.FirewallLpmKeyV4]struct{}, len(want))
	for _, key := range want {
		desired[key] = struct{}{}
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}
	var toDelete []bpf.FirewallLpmKeyV4
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV4
	var val uint8
	for iter.Next(&key, &val) {
		if _, ok := desired[key]; !ok {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range toDelete {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func syncLPMv6(m *ebpf.Map, want []bpf.FirewallLpmKeyV6) error {
	if m == nil {
		return nil
	}
	desired := make(map[bpf.FirewallLpmKeyV6]struct{}, len(want))
	for _, key := range want {
		desired[key] = struct{}{}
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}
	var toDelete []bpf.FirewallLpmKeyV6
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV6
	var val uint8
	for iter.Next(&key, &val) {
		if _, ok := desired[key]; !ok {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range toDelete {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func syncPortHash(m *ebpf.Map, ports []uint16) error {
	if m == nil {
		return nil
	}
	desired := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		desired[p] = struct{}{}
		if err := m.Put(p, uint8(1)); err != nil {
			return err
		}
	}
	var toDelete []uint16
	iter := m.Iterate()
	var key uint16
	var val uint8
	for iter.Next(&key, &val) {
		if _, ok := desired[key]; !ok {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range toDelete {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

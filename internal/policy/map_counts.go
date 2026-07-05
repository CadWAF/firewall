package policy

import (
	"github.com/cilium/ebpf"
	"github.com/huzenkon/waf-firewall/internal/bpf"
)

// MapCounts reports live BPF map entry counts (for diagnostics).
type MapCounts struct {
	WhitelistV4 int `json:"whitelist_v4"`
	WhitelistV6 int `json:"whitelist_v6"`
	BlocklistV4 int `json:"blocklist_v4"`
	BlocklistV6 int `json:"blocklist_v6"`
	TCPIn       int `json:"tcp_in"`
	UDPIn       int `json:"udp_in"`
	TCPOut      int `json:"tcp_out"`
	UDPOut      int `json:"udp_out"`
}

func CountMaps(objs *bpf.FirewallObjects) (MapCounts, error) {
	var c MapCounts
	var err error
	if c.WhitelistV4, err = countLPMv4(objs.WhitelistV4); err != nil {
		return c, err
	}
	if c.WhitelistV6, err = countLPMv6(objs.WhitelistV6); err != nil {
		return c, err
	}
	if c.BlocklistV4, err = countLPMv4(objs.BlocklistV4); err != nil {
		return c, err
	}
	if c.BlocklistV6, err = countLPMv6(objs.BlocklistV6); err != nil {
		return c, err
	}
	if c.TCPIn, err = countPortHash(objs.TcpInPorts); err != nil {
		return c, err
	}
	if c.UDPIn, err = countPortHash(objs.UdpInPorts); err != nil {
		return c, err
	}
	if c.TCPOut, err = countPortHash(objs.TcpOutPorts); err != nil {
		return c, err
	}
	if c.UDPOut, err = countPortHash(objs.UdpOutPorts); err != nil {
		return c, err
	}
	return c, nil
}

func countLPMv4(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	n := 0
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV4
	var val uint8
	for iter.Next(&key, &val) {
		n++
	}
	return n, iter.Err()
}

func countLPMv6(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	n := 0
	iter := m.Iterate()
	var key bpf.FirewallLpmKeyV6
	var val uint8
	for iter.Next(&key, &val) {
		n++
	}
	return n, iter.Err()
}

func countPortHash(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	n := 0
	iter := m.Iterate()
	var key uint16
	var val uint8
	for iter.Next(&key, &val) {
		n++
	}
	return n, iter.Err()
}

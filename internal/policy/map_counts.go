package policy

import (
	"net"

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

// PortInMap reports whether tcp_in_ports (or similar) contains port.
func PortInMap(m *ebpf.Map, port uint16) (bool, error) {
	if m == nil {
		return false, nil
	}
	var val uint8
	err := m.Lookup(port, &val)
	if err != nil {
		if isMissingMapKey(err) {
			return false, nil
		}
		return false, err
	}
	return val != 0, nil
}

// VerifyPortMapKeys ensures every configured port is present in the live BPF hash.
// Count-only checks miss the failure mode where map size matches but keys are wrong
// (false XDP drops on 80/443 while tcp_in/map_tcp_in both report 2).
func VerifyPortMapKeys(m *ebpf.Map, want []uint16) (missing []uint16, err error) {
	for _, p := range want {
		ok, lookupErr := PortInMap(m, p)
		if lookupErr != nil {
			return missing, lookupErr
		}
		if !ok {
			missing = append(missing, p)
		}
	}
	return missing, nil
}

// VerifyWhitelistV4Keys ensures each configured IPv4 allow entry is lookupable
// the same way the XDP program does (LPM prefixlen=32, wire-order addr).
func VerifyWhitelistV4Keys(m *ebpf.Map, ips []string) (missing []string, err error) {
	if m == nil {
		return ips, nil
	}
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		key := bpf.FirewallLpmKeyV4{Prefixlen: 32, Addr: ip4BPFKey(ip4)}
		var val uint8
		lookupErr := m.Lookup(key, &val)
		if lookupErr != nil {
			if isMissingMapKey(lookupErr) {
				missing = append(missing, raw)
				continue
			}
			return missing, lookupErr
		}
		if val == 0 {
			missing = append(missing, raw)
		}
	}
	return missing, nil
}

// VerifyWhitelistV6Keys is the IPv6 counterpart of VerifyWhitelistV4Keys.
// Previously only v4 was checked by the periodic integrity self-heal, so an
// IPv6-only admin allow entry could silently false-drop forever without
// tripping any alert or triggering RefreshMaps.
func VerifyWhitelistV6Keys(m *ebpf.Map, ips []string) (missing []string, err error) {
	if m == nil {
		return ips, nil
	}
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() != nil {
			continue
		}
		key := bpf.FirewallLpmKeyV6{Prefixlen: 128}
		copy(key.Addr[:], ip.To16())
		var val uint8
		lookupErr := m.Lookup(key, &val)
		if lookupErr != nil {
			if isMissingMapKey(lookupErr) {
				missing = append(missing, raw)
				continue
			}
			return missing, lookupErr
		}
		if val == 0 {
			missing = append(missing, raw)
		}
	}
	return missing, nil
}

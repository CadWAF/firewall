//go:build linux

package bpf

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Firewall struct {
	objs    *FirewallObjects
	xdpLink link.Link
	tcLink  *tcFilter
	iface   string
}

type tcFilter struct {
	linkIndex int
	handle    uint32
}

func NewFirewall(iface string) (*Firewall, error) {
	objs := &FirewallObjects{}
	if err := LoadFirewallObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	return &Firewall{objs: objs, iface: iface}, nil
}

func Load(iface string) (*Firewall, error) {
	f, err := NewFirewall(iface)
	if err != nil {
		return nil, err
	}
	if err := f.Attach(); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (f *Firewall) Objects() *FirewallObjects { return f.objs }
func (f *Firewall) Iface() string             { return f.iface }

func (f *Firewall) Attach() error {
	name := strings.ToLower(strings.TrimSpace(f.iface))
	if name == "" || name == "lo" || name == "docker0" ||
		strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "cni") {
		return fmt.Errorf("refusing XDP attach on virtual interface %q — use WAN NIC", f.iface)
	}

	// Orphaned XDP/TC from a crashed or partial stop would cause EBUSY.
	_ = DetachInterface(f.iface)

	iface, err := net.InterfaceByName(f.iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", f.iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   f.objs.XdpFirewall,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}
	f.xdpLink = xdpLink

	if os.Getenv("FIREWALL_EGRESS") == "false" {
		return nil
	}

	if err := ensureClsact(f.iface); err != nil {
		f.xdpLink.Close()
		return err
	}

	tc, err := attachTCEgress(f.iface, f.objs.TcEgress)
	if err != nil {
		f.xdpLink.Close()
		return fmt.Errorf("attach tc egress: %w", err)
	}
	f.tcLink = tc
	return nil
}

func ensureClsact(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			return nil
		}
	}
	clsact := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	return netlink.QdiscAdd(clsact)
}

func attachTCEgress(ifaceName string, prog *ebpf.Program) (*tcFilter, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    0x1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "tc_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return &tcFilter{linkIndex: link.Attrs().Index, handle: 0x1}, nil
}

func (f *Firewall) Close() error {
	var first error
	iface := f.iface

	if f.tcLink != nil {
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: f.tcLink.linkIndex,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    f.tcLink.handle,
				Protocol:  unix.ETH_P_ALL,
			},
		}
		if err := netlink.FilterDel(filter); err != nil && first == nil {
			first = err
		}
		f.tcLink = nil
	}
	if f.xdpLink != nil {
		if err := f.xdpLink.Close(); err != nil && first == nil {
			first = err
		}
		f.xdpLink = nil
	}
	if f.objs != nil {
		if err := f.objs.Close(); err != nil && first == nil {
			first = err
		}
		f.objs = nil
	}
	if iface != "" {
		if err := DetachInterface(iface); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type Stats struct {
	XDPPass uint64
	XDPDrop uint64
	TCPass  uint64
	TCDrop  uint64
}

func (f *Firewall) Stats() (Stats, error) {
	var s Stats
	if err := sumPerCPU(f.objs.XdpStats, &s.XDPPass, &s.XDPDrop); err != nil {
		return s, err
	}
	if err := sumPerCPU(f.objs.TcStats, &s.TCPass, &s.TCDrop); err != nil {
		return s, err
	}
	return s, nil
}

func sumPerCPU(m *ebpf.Map, pass, drop *uint64) error {
	if m == nil {
		return nil
	}
	var values []FirewallPktStats
	if err := m.Lookup(uint32(0), &values); err != nil {
		return err
	}
	for _, v := range values {
		*pass += v.Pass
		*drop += v.Drop
	}
	return nil
}

// DefaultInterface picks a non-virtual host NIC that is up and has an address.
// Prefer config.ResolveIface() (default route) for attach decisions.
func DefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if name == "docker0" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "cni") ||
			strings.HasPrefix(name, "flannel") || strings.HasPrefix(name, "virbr") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("no suitable physical network interface found (refusing docker/bridge/veth)")
}

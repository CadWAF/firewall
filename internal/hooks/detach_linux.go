//go:build linux

package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// Detach removes XDP and TC egress hooks from the interface via netlink.
// This alone is NOT enough while firewalld is running: Attach uses bpf_link
// (cilium link.AttachXDP), which stays active until the daemon closes it.
// Callers that need a hard clear must stop firewalld first (see ctl.HooksOff).
func Detach(iface string) error {
	if iface == "" {
		return fmt.Errorf("interface is required")
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	_ = netlink.LinkSetXdpFd(link, -1)

	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err == nil {
		for _, f := range filters {
			_ = netlink.FilterDel(f)
		}
	}

	qdiscs, err := netlink.QdiscList(link)
	if err == nil {
		for _, q := range qdiscs {
			if q.Type() == "clsact" {
				_ = netlink.QdiscDel(q)
			}
		}
	}

	// Fallback for orphaned programs netlink did not detach.
	out, _ := exec.Command("ip", "link", "show", "dev", iface).CombinedOutput()
	if strings.Contains(string(out), "xdp") {
		_ = exec.Command("ip", "link", "set", "dev", iface, "xdp", "off").Run()
	}
	if _, lookErr := exec.LookPath("tc"); lookErr == nil {
		_ = exec.Command("tc", "filter", "del", "dev", iface, "egress").Run()
		_ = exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()
	}

	matches, _ := filepath.Glob("/sys/fs/bpf/fwtest*")
	for _, p := range matches {
		_ = os.Remove(p)
	}
	return nil
}

// DetachVirtualLeftovers removes orphaned XDP/TC from Docker bridges and veths.
// engine used to attach via DefaultInterface() which often picked docker0/br-*.
func DetachVirtualLeftovers() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	var first error
	for _, link := range links {
		name := link.Attrs().Name
		n := strings.ToLower(name)
		virtual := n == "docker0" || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") ||
			strings.HasPrefix(n, "docker") || n == "cni0" || strings.HasPrefix(n, "cni-")
		if !virtual {
			continue
		}
		out, _ := exec.Command("ip", "link", "show", "dev", name).CombinedOutput()
		s := string(out)
		if !strings.Contains(s, "xdp") && !strings.Contains(s, "clsact") {
			// Still try qdisc cleanup cheaply when clsact exists.
			qdiscs, qerr := netlink.QdiscList(link)
			if qerr != nil {
				continue
			}
			hasClsact := false
			for _, q := range qdiscs {
				if q.Type() == "clsact" {
					hasClsact = true
					break
				}
			}
			if !hasClsact {
				continue
			}
		}
		if err := Detach(name); err != nil && first == nil {
			first = err
		}
	}
	return first
}

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

// Detach removes XDP and TC egress hooks from the interface, matching
// scripts/firewall-emergency-recover.sh behaviour.
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

package config

import (
	"fmt"
	"os/exec"
	"strings"
)

// IsVirtualIface reports interfaces that must never receive the host XDP/TC
// firewall. Attaching there drops Docker / container userspace traffic
// (bridge + veth churn from waf-filter compose) while leaving the WAN open.
func IsVirtualIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return true
	}
	switch n {
	case "lo", "docker0", "cni0", "flannel.1", "virbr0", "lxcbr0", "podman0":
		return true
	}
	prefixes := []string{
		"veth", "br-", "docker", "cni-", "flannel", "virbr", "vnet",
		"tap", "tun", "wg", "tailscale", "zt", "kube-", "cali", "nodelocaldns",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// ValidateAttachIface ensures the firewall attaches only to a real host NIC.
func ValidateAttachIface(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("firewall interface is empty")
	}
	if IsVirtualIface(name) {
		return fmt.Errorf("refusing to attach XDP/TC to virtual interface %q (docker/bridge/veth) — set FIREWALL_IFACE to the WAN NIC (eth0/ens*/enp*)", name)
	}
	return nil
}

func (c *Config) ResolveIface() (string, error) {
	if c.Iface != "" {
		// Explicit value is returned as-is so hooks-off can detach a
		// previously mis-attached docker/bridge interface.
		return c.Iface, nil
	}
	iface, err := defaultRouteIface()
	if err != nil {
		return "", err
	}
	return iface, nil
}

// ResolveAttachIface is for loading XDP/TC — never a Docker bridge/veth.
func (c *Config) ResolveAttachIface() (string, error) {
	iface, err := c.ResolveIface()
	if err != nil {
		return "", err
	}
	if err := ValidateAttachIface(iface); err != nil {
		return "", err
	}
	return iface, nil
}

func defaultRouteIface() (string, error) {
	out, err := exec.Command("ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("detect default interface: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	var candidates []string
	for _, line := range lines {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				candidates = append(candidates, fields[i+1])
				break
			}
		}
	}
	for _, iface := range candidates {
		if !IsVirtualIface(iface) {
			return iface, nil
		}
	}
	if len(candidates) > 0 {
		return "", fmt.Errorf("default route points only at virtual iface %q — set FIREWALL_IFACE explicitly", candidates[0])
	}
	return "", fmt.Errorf("could not detect default interface")
}

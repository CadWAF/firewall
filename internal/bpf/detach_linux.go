//go:build linux

package bpf

import "github.com/huzenkon/waf-firewall/internal/hooks"

func DetachInterface(iface string) error {
	return hooks.Detach(iface)
}

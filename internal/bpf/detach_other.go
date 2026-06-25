//go:build !linux

package bpf

import "fmt"

func DetachInterface(iface string) error {
	return fmt.Errorf("firewall bpf loader requires linux")
}

//go:build !linux

package hooks

import "fmt"

func Detach(iface string) error {
	return fmt.Errorf("firewall hooks require linux")
}

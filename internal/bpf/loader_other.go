//go:build !linux

package bpf

import "fmt"

type Firewall struct{}

type Stats struct {
	XDPPass uint64
	XDPDrop uint64
	TCPass  uint64
	TCDrop  uint64
}

func NewFirewall(iface string) (*Firewall, error) {
	return nil, fmt.Errorf("firewall bpf loader requires linux")
}

func Load(iface string) (*Firewall, error) {
	return nil, fmt.Errorf("firewall bpf loader requires linux")
}

func (f *Firewall) Attach() error { return fmt.Errorf("requires linux") }

func (f *Firewall) Objects() *FirewallObjects { return nil }
func (f *Firewall) Iface() string             { return "" }
func (f *Firewall) Close() error              { return nil }
func (f *Firewall) Stats() (Stats, error)     { return Stats{}, fmt.Errorf("requires linux") }

func DefaultInterface() (string, error) {
	return "", fmt.Errorf("firewall requires linux")
}

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/huzenkon/waf-firewall/internal/config"
)

func TestEnsureSafePortsAddsQUICWhen443Open(t *testing.T) {
	pc := &config.PortsConfig{
		TCPIn:  []uint16{80, 443},
		UDPIn:  []uint16{53},
		TCPOut: []uint16{80, 443},
	}
	EnsureSafePorts(pc)
	if containsPort(pc.TCPIn, 22) {
		t.Fatalf("ssh should not be injected unless FIREWALL_ENSURE_SSH_IN=true: %v", pc.TCPIn)
	}
	if !containsPort(pc.UDPIn, 443) {
		t.Fatalf("udp_in missing quic: %v", pc.UDPIn)
	}
}

func TestEnsureSafePortsAddsSSHWhenEnabled(t *testing.T) {
	t.Setenv("FIREWALL_ENSURE_SSH_IN", "true")
	pc := &config.PortsConfig{TCPIn: []uint16{443}}
	EnsureSafePorts(pc)
	if !containsPort(pc.TCPIn, 22) {
		t.Fatalf("tcp_in missing ssh: %v", pc.TCPIn)
	}
}

func TestValidateSSHReachableRejectsEmptyAllow(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	if err := os.WriteFile(allow, []byte("# empty\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pc := &config.PortsConfig{TCPIn: []uint16{443}}
	if err := ValidateSSHReachable(allow, pc); err == nil {
		t.Fatal("expected error when ssh missing and allow empty")
	}
}

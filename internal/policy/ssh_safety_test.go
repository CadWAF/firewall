package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/huzenkon/waf-firewall/internal/config"
)

func TestEnsureSSHSafetyAllowsWhitelistWithoutPort22(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	deny := filepath.Join(dir, "firewall.deny")
	ports := filepath.Join(dir, "ports.conf")

	if err := os.WriteFile(allow, []byte("10.8.0.2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ports, []byte("tcp_in = 80,443\nudp_in =\ntcp_out = 80,443\nudp_out =\nallow_localhost = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// No SSH_CLIENT — typical firewallctl activate / systemctl path.
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")

	if err := EnsureSSHSafety(allow, deny, ports); err != nil {
		t.Fatalf("expected whitelist-only SSH to be allowed: %v", err)
	}
}

func TestEnsureSSHSafetyAcceptsCIDRCoveringClient(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	deny := filepath.Join(dir, "firewall.deny")
	ports := filepath.Join(dir, "ports.conf")

	if err := os.WriteFile(allow, []byte("10.8.0.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ports, []byte("tcp_in = 80,443\nudp_in =\ntcp_out = 80,443\nudp_out =\nallow_localhost = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSH_CLIENT", "10.8.0.55 12345 22")
	t.Setenv("SSH_CONNECTION", "")

	if err := EnsureSSHSafety(allow, deny, ports); err != nil {
		t.Fatalf("VPN CIDR should cover SSH client: %v", err)
	}
}

func TestEnsureSSHSafetyRejectsEmptyAllowWithoutSSHPort(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	deny := filepath.Join(dir, "firewall.deny")
	ports := filepath.Join(dir, "ports.conf")

	if err := os.WriteFile(allow, []byte("# none\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ports, []byte("tcp_in = 80,443\nudp_in =\ntcp_out = 80,443\nudp_out =\nallow_localhost = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")

	if err := EnsureSSHSafety(allow, deny, ports); err == nil {
		t.Fatal("expected error when allow empty and ssh not in tcp_in")
	}
}

func TestValidateSSHReachableAllowsWhitelistOnly(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	if err := os.WriteFile(allow, []byte("203.0.113.10\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pc := &config.PortsConfig{TCPIn: []uint16{80, 443}}
	if err := ValidateSSHReachable(allow, pc); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestIPCoveredByAllowCIDR(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	if err := os.WriteFile(allow, []byte("10.8.0.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ok, err := ipCoveredByAllow(allow, "10.8.0.9")
	if err != nil || !ok {
		t.Fatalf("expected covered, ok=%v err=%v", ok, err)
	}
	ok, err = ipCoveredByAllow(allow, "10.9.0.1")
	if err != nil || ok {
		t.Fatalf("expected not covered, ok=%v err=%v", ok, err)
	}
}

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/huzenkon/waf-firewall/internal/policy"
)

func TestLoadState(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "firewall.allow")
	deny := filepath.Join(dir, "firewall.deny")
	ports := filepath.Join(dir, "ports.conf")

	if err := os.WriteFile(allow, []byte("1.2.3.4\n# comment\ntcp|in|d=80|s=10.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("198.51.100.99\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ports, []byte("tcp_in = 22,80\nudp_in = 53\ntcp_out = 443\nudp_out = 53\nallow_localhost = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	st, err := policy.LoadState(allow, deny, ports)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Whitelist) != 1 || st.Whitelist[0] != "1.2.3.4" {
		t.Fatalf("whitelist = %v", st.Whitelist)
	}
	if len(st.Blocklist) != 1 {
		t.Fatalf("blocklist = %v", st.Blocklist)
	}
	if len(st.Rules) != 1 {
		t.Fatalf("rules = %d", len(st.Rules))
	}
	if len(st.Ports.TCPIn) != 2 {
		t.Fatalf("tcp_in = %v", st.Ports.TCPIn)
	}
}

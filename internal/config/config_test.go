package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewalld.env")
	content := "# comment\nFIREWALL_API_TOKEN=from-file\nFIREWALL_IFACE=eth1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FIREWALL_API_TOKEN", "")
	t.Setenv("FIREWALL_IFACE", "")

	LoadEnvFile(path)

	if got := os.Getenv("FIREWALL_API_TOKEN"); got != "from-file" {
		t.Fatalf("FIREWALL_API_TOKEN = %q, want from-file", got)
	}
	if got := os.Getenv("FIREWALL_IFACE"); got != "eth1" {
		t.Fatalf("FIREWALL_IFACE = %q, want eth1", got)
	}
}

func TestLoadEnvFileDoesNotOverrideExistingEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewalld.env")
	if err := os.WriteFile(path, []byte("FIREWALL_API_TOKEN=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FIREWALL_API_TOKEN", "already-set")
	LoadEnvFile(path)

	if got := os.Getenv("FIREWALL_API_TOKEN"); got != "already-set" {
		t.Fatalf("FIREWALL_API_TOKEN = %q, want already-set", got)
	}
}

func TestLoadRequiresAPIKey(t *testing.T) {
	t.Setenv("FIREWALL_API_TOKEN", "")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when FIREWALL_API_TOKEN is missing")
	}
}

func TestLoadWithAPIKey(t *testing.T) {
	t.Setenv("FIREWALL_API_TOKEN", "test-secret")
	t.Setenv("FIREWALL_CONFIG_DIR", "/tmp/firewall-test")
	t.Setenv("FIREWALL_LISTEN_ADDR", "127.0.0.1:9091")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.APIKey != "test-secret" {
		t.Fatalf("APIKey = %q, want test-secret", cfg.APIKey)
	}
	if cfg.ConfigDir != "/tmp/firewall-test" {
		t.Fatalf("ConfigDir = %q, want /tmp/firewall-test", cfg.ConfigDir)
	}
	if cfg.ListenAddr != "127.0.0.1:9091" {
		t.Fatalf("ListenAddr = %q, want 127.0.0.1:9091", cfg.ListenAddr)
	}
}

func TestLoadPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports.conf")
	content := "tcp_in = 22,80-82\nudp_in = 53\nallow_localhost = false\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	pc, err := LoadPorts(path)
	if err != nil {
		t.Fatalf("LoadPorts() error: %v", err)
	}
	if len(pc.TCPIn) != 4 || pc.TCPIn[0] != 22 || pc.TCPIn[3] != 82 {
		t.Fatalf("TCPIn = %v, want [22 80 81 82]", pc.TCPIn)
	}
	if len(pc.UDPIn) != 1 || pc.UDPIn[0] != 53 {
		t.Fatalf("UDPIn = %v, want [53]", pc.UDPIn)
	}
	if pc.AllowLocalhost {
		t.Fatal("AllowLocalhost = true, want false")
	}
}

func TestLoadPortsInvalidBool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports.conf")
	if err := os.WriteFile(path, []byte("allow_localhost = maybe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPorts(path)
	if err == nil {
		t.Fatal("expected error for invalid allow_localhost value")
	}
}

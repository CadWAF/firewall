package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/huzenkon/waf-firewall/internal/ports"
)

// Version is the daemon version. Overridden at release build time via
// -ldflags "-X .../internal/config.Version=<tag>"; the default tracks the
// source tree between releases.
var Version = "0.3.2"

type Config struct {
	ConfigDir  string
	ListenAddr string
	APIKey     string
	Iface      string

	// Where refused sources are kept. Empty disables recording entirely: on a
	// node with no disk to spare, counting is still useful and the file is not.
	DropLogPath string

	// How long a refused source stays on record after it goes quiet.
	DropRetention time.Duration
}

// DropLogEnabled reports whether refusals are written to disk.
func (c *Config) DropLogEnabled() bool { return c.DropLogPath != "" }

func Load() (*Config, error) {
	LoadEnvFile(DefaultEnvPath())
	cfg := &Config{
		ConfigDir:     envOr("FIREWALL_CONFIG_DIR", "/etc/firewall"),
		ListenAddr:    envOr("FIREWALL_LISTEN_ADDR", "127.0.0.1:9090"),
		APIKey:        os.Getenv("FIREWALL_API_TOKEN"),
		Iface:         os.Getenv("FIREWALL_IFACE"),
		DropLogPath:   dropLogPath(),
		DropRetention: dropRetention(),
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("FIREWALL_API_TOKEN is required")
	}
	return cfg, nil
}

func DefaultEnvPath() string {
	return "/etc/firewall/firewalld.env"
}

// LoadCLI reads config for firewallctl. API token is optional.
func LoadCLI() (*Config, error) {
	LoadEnvFile(DefaultEnvPath())
	return &Config{
		ConfigDir:     envOr("FIREWALL_CONFIG_DIR", "/etc/firewall"),
		ListenAddr:    envOr("FIREWALL_LISTEN_ADDR", "127.0.0.1:9090"),
		APIKey:        os.Getenv("FIREWALL_API_TOKEN"),
		Iface:         os.Getenv("FIREWALL_IFACE"),
		DropLogPath:   dropLogPath(),
		DropRetention: dropRetention(),
	}, nil
}

func LoadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, strings.TrimSpace(val))
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c *Config) AllowPath() string { return filepath.Join(c.ConfigDir, "firewall.allow") }
func (c *Config) DenyPath() string  { return filepath.Join(c.ConfigDir, "firewall.deny") }
func (c *Config) PortsPath() string { return filepath.Join(c.ConfigDir, "ports.conf") }

type PortsConfig struct {
	TCPIn          []uint16
	UDPIn          []uint16
	TCPOut         []uint16
	UDPOut         []uint16
	AllowLocalhost bool
}

func LoadPorts(path string) (*PortsConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pc := &PortsConfig{AllowLocalhost: true}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch key {
		case "tcp_in":
			pc.TCPIn, err = ports.ParseList(val)
		case "udp_in":
			pc.UDPIn, err = ports.ParseList(val)
		case "tcp_out":
			pc.TCPOut, err = ports.ParseList(val)
		case "udp_out":
			pc.UDPOut, err = ports.ParseList(val)
		case "allow_localhost":
			pc.AllowLocalhost, err = strconv.ParseBool(val)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", line, err)
		}
	}
	return pc, sc.Err()
}

func SavePorts(path string, pc *PortsConfig) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ports other servers may connect TO on this host (inbound allow)\n")
	fmt.Fprintf(&b, "tcp_in = %s\n", ports.FormatList(pc.TCPIn))
	fmt.Fprintf(&b, "udp_in = %s\n", ports.FormatList(pc.UDPIn))
	fmt.Fprintf(&b, "\n# Ports this host's services may connect TO on remote servers (outbound allow)\n")
	fmt.Fprintf(&b, "tcp_out = %s\n", ports.FormatList(pc.TCPOut))
	fmt.Fprintf(&b, "udp_out = %s\n", ports.FormatList(pc.UDPOut))
	fmt.Fprintf(&b, "\n# Always allow loopback traffic\n")
	fmt.Fprintf(&b, "allow_localhost = %t\n", pc.AllowLocalhost)
	return os.WriteFile(path, []byte(b.String()), 0644)
}

// dropLogPath defaults to a file beside the other firewall state. Set
// FIREWALL_DROP_LOG=off to turn recording off.
func dropLogPath() string {
	v := strings.TrimSpace(os.Getenv("FIREWALL_DROP_LOG"))
	switch strings.ToLower(v) {
	case "off", "false", "0", "none":
		return ""
	case "":
		return "/var/lib/firewall/drops.sqlite"
	default:
		return v
	}
}

func dropRetention() time.Duration {
	v := strings.TrimSpace(os.Getenv("FIREWALL_DROP_RETENTION"))
	if v == "" {
		return 14 * 24 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 14 * 24 * time.Hour
	}
	return d
}

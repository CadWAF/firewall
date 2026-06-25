package config

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const Version = "0.1.0"

type Config struct {
	ConfigDir  string
	ListenAddr string
	APIKey     string
	Iface      string
}

func Load() (*Config, error) {
	LoadEnvFile(DefaultEnvPath())
	cfg := &Config{
		ConfigDir:  envOr("FIREWALL_CONFIG_DIR", "/etc/firewall"),
		ListenAddr: envOr("FIREWALL_LISTEN_ADDR", "127.0.0.1:9090"),
		APIKey:     os.Getenv("FIREWALL_API_TOKEN"),
		Iface:      os.Getenv("FIREWALL_IFACE"),
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
		ConfigDir:  envOr("FIREWALL_CONFIG_DIR", "/etc/firewall"),
		ListenAddr: envOr("FIREWALL_LISTEN_ADDR", "127.0.0.1:9090"),
		APIKey:     os.Getenv("FIREWALL_API_TOKEN"),
		Iface:      os.Getenv("FIREWALL_IFACE"),
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

func (c *Config) ResolveIface() (string, error) {
	if c.Iface != "" {
		return c.Iface, nil
	}
	iface, err := defaultRouteIface()
	if err != nil {
		return "", err
	}
	return iface, nil
}

func defaultRouteIface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("detect default interface: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not detect default interface")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c *Config) AllowPath() string  { return filepath.Join(c.ConfigDir, "firewall.allow") }
func (c *Config) DenyPath() string   { return filepath.Join(c.ConfigDir, "firewall.deny") }
func (c *Config) PortsPath() string  { return filepath.Join(c.ConfigDir, "ports.conf") }

type PortsConfig struct {
	TCPIn           []uint16
	UDPIn           []uint16
	TCPOut          []uint16
	UDPOut          []uint16
	AllowLocalhost  bool
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
			pc.TCPIn, err = parsePortList(val)
		case "udp_in":
			pc.UDPIn, err = parsePortList(val)
		case "tcp_out":
			pc.TCPOut, err = parsePortList(val)
		case "udp_out":
			pc.UDPOut, err = parsePortList(val)
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
	fmt.Fprintf(&b, "tcp_in = %s\n", formatPortList(pc.TCPIn))
	fmt.Fprintf(&b, "udp_in = %s\n", formatPortList(pc.UDPIn))
	fmt.Fprintf(&b, "\n# Ports this host's services may connect TO on remote servers (outbound allow)\n")
	fmt.Fprintf(&b, "tcp_out = %s\n", formatPortList(pc.TCPOut))
	fmt.Fprintf(&b, "udp_out = %s\n", formatPortList(pc.UDPOut))
	fmt.Fprintf(&b, "\n# Always allow loopback traffic\n")
	fmt.Fprintf(&b, "allow_localhost = %t\n", pc.AllowLocalhost)
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func parsePortList(s string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var ports []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "_") {
			rangePorts, err := expandPortRange(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, rangePorts...)
			continue
		}
		p, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, err
		}
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

func expandPortRange(s string) ([]uint16, error) {
	parts := strings.SplitN(s, "_", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return nil, err
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil {
		return nil, err
	}
	if hi < lo {
		return nil, fmt.Errorf("invalid port range %q", s)
	}
	var ports []uint16
	for p := lo; p <= hi; p++ {
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

func formatPortList(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

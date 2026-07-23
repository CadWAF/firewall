package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/parser"
)

// EnsureActiveSSHClientsAllow appends IPs of established SSH sessions to the
// allow file so a reload cannot lock out the current administrator.
func EnsureActiveSSHClientsAllow(allowPath string) error {
	for _, ip := range activeSSHClientIPs() {
		if ip == "" {
			continue
		}
		if err := parser.AppendIPToFile(allowPath, ip); err != nil {
			return err
		}
	}
	return nil
}

// EnsureSSHSafety keeps SSH reachable after reload/activate.
//
// Intended model: either open SSH in tcp_in, OR keep administrators in
// firewall.allow (typically VPN / bastion IPs) without exposing port 22 to the world.
func EnsureSSHSafety(allowPath, denyPath, portsPath string) error {
	_ = denyPath

	if err := EnsureActiveSSHClientsAllow(allowPath); err != nil {
		return err
	}
	if ip := sshClientIP(); ip != "" {
		covered, err := ipCoveredByAllow(allowPath, ip)
		if err != nil {
			return err
		}
		if !covered {
			if err := parser.AppendIPToFile(allowPath, ip); err != nil {
				return err
			}
		}
	}

	ports, err := config.LoadPorts(portsPath)
	if err != nil {
		return err
	}
	if containsPort(ports.TCPIn, sshPort()) {
		return nil
	}

	// Whitelist-only SSH is valid: tcp_in may omit 22 when firewall.allow has entries.
	return ValidateSSHReachable(allowPath, ports)
}

func sshClientIP() string {
	for _, key := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if v := os.Getenv(key); v != "" {
			return strings.Fields(v)[0]
		}
	}
	return ""
}

func activeSSHClientIPs() []string {
	port := sshPort()
	out, err := exec.Command("ss", "-H", "-tn", "state", "established", "sport", fmt.Sprintf("=:%d", port)).Output()
	if err != nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		peer := fields[3]
		ip, _, ok := strings.Cut(peer, ":")
		if !ok || ip == "" || seen[ip] {
			continue
		}
		// ss may print IPv6 as [addr]:port
		ip = strings.Trim(ip, "[]")
		if strings.Count(ip, ".") != 3 && !strings.Contains(ip, ":") {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips
}

// ipCoveredByAllow reports whether ip is listed in firewall.allow exactly or
// falls inside an allow CIDR (so VPN ranges work without opening tcp_in=22).
func ipCoveredByAllow(allowPath, ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid client IP %q", ipStr)
	}
	entries, err := parser.ParseFile(allowPath, parser.ActionPass)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Kind != parser.EntrySimpleIP || e.IP == nil {
			continue
		}
		if e.Raw == ipStr {
			return true, nil
		}
		if e.IP.Equal(ip) {
			return true, nil
		}
		prefix := e.PrefixLen
		if prefix <= 0 {
			if e.IP.To4() != nil {
				prefix = 32
			} else {
				prefix = 128
			}
		}
		var mask net.IPMask
		if ip.To4() != nil && e.IP.To4() != nil {
			mask = net.CIDRMask(prefix, 32)
			if ip.Mask(mask).Equal(e.IP.To4().Mask(mask)) {
				return true, nil
			}
			continue
		}
		if ip.To4() == nil && e.IP.To4() == nil {
			mask = net.CIDRMask(prefix, 128)
			if ip.Mask(mask).Equal(e.IP.Mask(mask)) {
				return true, nil
			}
		}
	}
	return false, nil
}

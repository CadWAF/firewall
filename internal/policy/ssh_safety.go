package policy

import (
	"bufio"
	"bytes"
	"fmt"
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

// EnsureSSHSafety keeps the current SSH session reachable after reload.
func EnsureSSHSafety(allowPath, denyPath, portsPath string) error {
	if err := EnsureActiveSSHClientsAllow(allowPath); err != nil {
		return err
	}
	if ip := sshClientIP(); ip != "" {
		if err := parser.AppendIPToFile(allowPath, ip); err != nil {
			return err
		}
	}

	ports, err := config.LoadPorts(portsPath)
	if err != nil {
		return err
	}
	if containsPort(ports.TCPIn, sshPort()) {
		return nil
	}

	st, err := LoadState(allowPath, denyPath, portsPath)
	if err != nil {
		return err
	}
	if len(st.Whitelist) == 0 {
		return fmt.Errorf("tcp_in has no port %d and firewall.allow is empty — refusing to lock out SSH", sshPort())
	}

	clientIP := sshClientIP()
	if clientIP == "" {
		return fmt.Errorf("tcp_in has no port %d — add your IP to firewall.allow or restore tcp_in=%d before reload", sshPort(), sshPort())
	}
	for _, v := range st.Whitelist {
		if v == clientIP {
			return nil
		}
	}
	return fmt.Errorf("tcp_in has no port %d and %s is not in firewall.allow", sshPort(), clientIP)
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
		if strings.Count(ip, ".") != 3 && !strings.Contains(ip, ":") {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	return ips
}

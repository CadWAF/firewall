package ctl

import (
	"fmt"
	"os"
	"strings"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/parser"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

func sshClientIP() string {
	for _, key := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if v := os.Getenv(key); v != "" {
			return strings.Fields(v)[0]
		}
	}
	return ""
}

// ensureSSHSafety keeps the current SSH session reachable after reload:
// whitelists SSH_CLIENT and all established :22 peers, and refuses reload
// when tcp_in excludes 22 and no SSH client IP can be whitelisted.
func ensureSSHSafety(cfg *config.Config) error {
	if err := policy.EnsureActiveSSHClientsAllow(cfg.AllowPath()); err != nil {
		return err
	}
	if ip := sshClientIP(); ip != "" {
		if err := parser.AppendIPToFile(cfg.AllowPath(), ip); err != nil {
			return err
		}
	}

	ports, err := config.LoadPorts(cfg.PortsPath())
	if err != nil {
		return err
	}
	if portListContains(ports.TCPIn, 22) {
		return nil
	}

	st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
	if err != nil {
		return err
	}
	if len(st.Whitelist) == 0 {
		return fmt.Errorf("tcp_in has no port 22 and firewall.allow is empty — refusing to lock out SSH")
	}

	clientIP := sshClientIP()
	if clientIP == "" {
		return fmt.Errorf("tcp_in has no port 22 — add your IP to firewall.allow or restore tcp_in=22 before reload")
	}
	if !ipInList(st.Whitelist, clientIP) {
		return fmt.Errorf("tcp_in has no port 22 and %s is not in firewall.allow", clientIP)
	}
	return nil
}

func portListContains(ports []uint16, p uint16) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}

func ipInList(list []string, ip string) bool {
	for _, v := range list {
		if v == ip {
			return true
		}
	}
	return false
}

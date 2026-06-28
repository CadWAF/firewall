package policy

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"

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

func activeSSHClientIPs() []string {
	out, err := exec.Command("ss", "-H", "-tn", "state", "established", "sport", "=:22").Output()
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
		// Local is server:22; peer is client:ephemeral.
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

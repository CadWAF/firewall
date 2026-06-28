package ctl

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/hooks"
	"github.com/huzenkon/waf-firewall/internal/parser"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

const serviceName = "firewalld"

func Activate(cfg *config.Config) error {
	active, err := isServiceActive()
	if err != nil {
		return err
	}
	if active {
		return nil
	}
	if err := HooksOff(cfg); err != nil {
		return err
	}
	if err := ensureSSHSafety(cfg); err != nil {
		return err
	}
	return runSystemctl("start")
}

func Deactivate(cfg *config.Config) error {
	if err := runSystemctl("stop"); err != nil {
		return err
	}
	return HooksOff(cfg)
}

func Reactivate(cfg *config.Config) error {
	if err := Deactivate(cfg); err != nil {
		return err
	}
	return Activate(cfg)
}

func HooksOff(cfg *config.Config) error {
	iface, err := cfg.ResolveIface()
	if err != nil {
		return err
	}
	return hooks.Detach(iface)
}

func Status(cfg *config.Config) (StatusInfo, error) {
	active, _ := isServiceActive()
	iface, err := cfg.ResolveIface()
	if err != nil {
		return StatusInfo{}, err
	}

	info := StatusInfo{
		Service:   serviceState(active),
		Interface: iface,
	}
	if active {
		info.API = "http://" + cfg.ListenAddr
		c, _, _, err := currentCounts(cfg)
		if err == nil {
			info.Policy = c
			info.PolicySource = "memory"
		}
	} else {
		st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
		if err == nil {
			info.Policy = st.Counts()
			info.PolicySource = "config"
		}
	}
	return info, nil
}

func ListIPs(cfg *config.Config, which string) (ListResult, error) {
	allow, err := listSimpleIPs(cfg.AllowPath())
	if err != nil {
		return ListResult{}, fmt.Errorf("firewall.allow: %w", err)
	}
	block, err := listSimpleIPs(cfg.DenyPath())
	if err != nil {
		return ListResult{}, fmt.Errorf("firewall.deny: %w", err)
	}
	switch which {
	case "all", "":
		return ListResult{Allow: allow, Block: block}, nil
	case "allow", "whitelist", "white":
		return ListResult{Allow: allow}, nil
	case "block", "deny", "blacklist", "black":
		return ListResult{Block: block}, nil
	default:
		return ListResult{}, fmt.Errorf("unknown list: %s (use allow or block)", which)
	}
}

func listSimpleIPs(path string) ([]string, error) {
	entries, err := parser.ParseFile(path, parser.ActionPass)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, e := range entries {
		if e.Kind == parser.EntrySimpleIP {
			ips = append(ips, e.Raw)
		}
	}
	return ips, nil
}

func validateSimpleIP(ip string) error {
	if _, err := parser.ParseLine(ip, parser.ActionPass); err != nil {
		return fmt.Errorf("invalid ip: %w", err)
	}
	if strings.Contains(ip, "|") {
		return fmt.Errorf("invalid ip: complex rules are not supported here")
	}
	return nil
}

func runSystemctl(action string) error {
	cmd := exec.Command("systemctl", action, serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %s: %w", action, serviceName, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func isServiceActive() (bool, error) {
	cmd := exec.Command("systemctl", "is-active", "--quiet", serviceName)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 3 {
		return false, nil
	}
	return false, err
}

func serviceState(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

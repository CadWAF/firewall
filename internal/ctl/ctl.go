package ctl

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/hooks"
	"github.com/huzenkon/waf-firewall/internal/parser"
)

const serviceName = "firewalld"

func AllowIP(cfg *config.Config, ip string) error {
	if err := validateSimpleIP(ip); err != nil {
		return err
	}
	if err := parser.AppendIPToFile(cfg.AllowPath(), ip); err != nil {
		return err
	}
	return reloadIfRunning(cfg)
}

func BlockIP(cfg *config.Config, ip string) error {
	if err := validateSimpleIP(ip); err != nil {
		return err
	}
	if err := parser.AppendIPToFile(cfg.DenyPath(), ip); err != nil {
		return err
	}
	return reloadIfRunning(cfg)
}

func UnallowIP(cfg *config.Config, ip string) error {
	if err := parser.RemoveIPFromFile(cfg.AllowPath(), ip); err != nil {
		return err
	}
	return reloadIfRunning(cfg)
}

func UnblockIP(cfg *config.Config, ip string) error {
	if err := parser.RemoveIPFromFile(cfg.DenyPath(), ip); err != nil {
		return err
	}
	return reloadIfRunning(cfg)
}

func Activate() error {
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
	return Activate()
}

func HooksOff(cfg *config.Config) error {
	iface, err := cfg.ResolveIface()
	if err != nil {
		return err
	}
	return hooks.Detach(iface)
}

func Status(cfg *config.Config) (string, error) {
	active, _ := isServiceActive()
	iface, err := cfg.ResolveIface()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "service: %s\n", serviceState(active))
	fmt.Fprintf(&b, "interface: %s\n", iface)
	if active {
		fmt.Fprintf(&b, "api: http://%s\n", cfg.ListenAddr)
	}
	return b.String(), nil
}

func ListIPs(cfg *config.Config) (allow, block []string, err error) {
	allow, err = listSimpleIPs(cfg.AllowPath())
	if err != nil {
		return nil, nil, fmt.Errorf("firewall.allow: %w", err)
	}
	block, err = listSimpleIPs(cfg.DenyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("firewall.deny: %w", err)
	}
	return allow, block, nil
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

func reloadIfRunning(cfg *config.Config) error {
	active, err := isServiceActive()
	if err != nil {
		return err
	}
	if !active {
		return nil
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("FIREWALL_API_TOKEN is required to reload a running daemon")
	}
	url := "http://" + cfg.ListenAddr + "/api/v1/reload"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("reload request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reload failed: HTTP %d", resp.StatusCode)
	}
	return nil
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

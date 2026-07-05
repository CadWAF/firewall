package ctl

import (
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

func ensureSSHSafety(cfg *config.Config) error {
	return policy.EnsureSSHSafety(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
}

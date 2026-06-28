package ctl

import (
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/parser"
)

func AllowIP(cfg *config.Config, ip string) (IPChangeResult, error) {
	if err := validateSimpleIP(ip); err != nil {
		return IPChangeResult{}, err
	}
	before, fromMem, active, err := currentCounts(cfg)
	if err != nil {
		return IPChangeResult{}, err
	}
	if err := parser.AppendIPToFile(cfg.AllowPath(), ip); err != nil {
		return IPChangeResult{}, err
	}
	applied, err := commitPolicy(cfg, before, fromMem, active)
	if err != nil {
		return IPChangeResult{}, err
	}
	return IPChangeResult{Action: "allowed", IP: ip, ApplyResult: applied}, nil
}

func BlockIP(cfg *config.Config, ip string) (IPChangeResult, error) {
	if err := validateSimpleIP(ip); err != nil {
		return IPChangeResult{}, err
	}
	before, fromMem, active, err := currentCounts(cfg)
	if err != nil {
		return IPChangeResult{}, err
	}
	if err := parser.AppendIPToFile(cfg.DenyPath(), ip); err != nil {
		return IPChangeResult{}, err
	}
	applied, err := commitPolicy(cfg, before, fromMem, active)
	if err != nil {
		return IPChangeResult{}, err
	}
	return IPChangeResult{Action: "blocked", IP: ip, ApplyResult: applied}, nil
}

func UnallowIP(cfg *config.Config, ip string) (IPChangeResult, error) {
	before, fromMem, active, err := currentCounts(cfg)
	if err != nil {
		return IPChangeResult{}, err
	}
	if err := parser.RemoveIPFromFile(cfg.AllowPath(), ip); err != nil {
		return IPChangeResult{}, err
	}
	applied, err := commitPolicy(cfg, before, fromMem, active)
	if err != nil {
		return IPChangeResult{}, err
	}
	return IPChangeResult{Action: "unallowed", IP: ip, ApplyResult: applied}, nil
}

func UnblockIP(cfg *config.Config, ip string) (IPChangeResult, error) {
	before, fromMem, active, err := currentCounts(cfg)
	if err != nil {
		return IPChangeResult{}, err
	}
	if err := parser.RemoveIPFromFile(cfg.DenyPath(), ip); err != nil {
		return IPChangeResult{}, err
	}
	applied, err := commitPolicy(cfg, before, fromMem, active)
	if err != nil {
		return IPChangeResult{}, err
	}
	return IPChangeResult{Action: "unblocked", IP: ip, ApplyResult: applied}, nil
}

func Reload(cfg *config.Config) (ApplyResult, error) {
	return applyPolicy(cfg)
}

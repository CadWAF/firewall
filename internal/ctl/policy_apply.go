package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

// ApplyResult reports policy counts before and after a change.
type ApplyResult struct {
	Before   policy.Counts `json:"before"`
	After    policy.Counts `json:"after"`
	FromMem  bool          `json:"from_memory"`
	Inactive bool          `json:"inactive"`
}

func (r ApplyResult) FormatText() string {
	var b strings.Builder
	if r.FromMem {
		fmt.Fprintf(&b, "before (memory): %s\n", r.Before)
	} else {
		fmt.Fprintf(&b, "before (config): %s\n", r.Before)
	}
	if r.Inactive {
		fmt.Fprintf(&b, "after  (config): %s — firewalld inactive, activate to apply\n", r.After)
		return b.String()
	}
	fmt.Fprintf(&b, "after  (memory): %s\n", r.After)
	return b.String()
}

func currentCounts(cfg *config.Config) (policy.Counts, bool, bool, error) {
	active, err := isServiceActive()
	if err != nil {
		return policy.Counts{}, false, false, err
	}
	if !active {
		st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
		if err != nil {
			return policy.Counts{}, false, false, err
		}
		return st.Counts(), false, false, nil
	}
	c, err := fetchDaemonCounts(cfg)
	if err != nil {
		return policy.Counts{}, false, true, err
	}
	return c, true, true, nil
}

func fetchDaemonCounts(cfg *config.Config) (policy.Counts, error) {
	health, err := fetchDaemonHealth(cfg)
	if err != nil {
		return policy.Counts{}, err
	}
	return health.Policy, nil
}

type daemonHealth struct {
	Policy policy.Counts `json:"policy"`
	Stats  *PacketStats  `json:"stats"`
}

func fetchDaemonHealth(cfg *config.Config) (*daemonHealth, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + cfg.ListenAddr + "/health")
	if err != nil {
		return nil, fmt.Errorf("daemon health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon health: HTTP %d", resp.StatusCode)
	}
	var health daemonHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("daemon health: %w", err)
	}
	return &health, nil
}

func applyPolicy(cfg *config.Config) (ApplyResult, error) {
	before, fromMem, active, err := currentCounts(cfg)
	if err != nil {
		return ApplyResult{}, err
	}
	return commitPolicy(cfg, before, fromMem, active)
}

func commitPolicy(cfg *config.Config, before policy.Counts, fromMem, active bool) (ApplyResult, error) {
	result := ApplyResult{
		Before:   before,
		FromMem:  fromMem,
		Inactive: !active,
	}

	if !active {
		st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
		if err != nil {
			return ApplyResult{}, err
		}
		result.After = st.Counts()
		return result, nil
	}

	if err := ensureSSHSafety(cfg); err != nil {
		return ApplyResult{}, err
	}

	if err := runSystemctl("reload"); err != nil {
		return ApplyResult{}, err
	}

	after, _, _, err := currentCounts(cfg)
	if err != nil {
		return ApplyResult{}, err
	}
	result.After = after
	result.FromMem = true
	return result, nil
}

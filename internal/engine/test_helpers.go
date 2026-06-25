package engine

import "github.com/huzenkon/waf-firewall/internal/config"

// NewTestEngine returns an Engine shell for HTTP handler tests (no BPF attached).
func NewTestEngine(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg, stopCh: make(chan struct{})}
}

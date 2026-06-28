package engine

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/huzenkon/waf-firewall/internal/bpf"
	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

type Engine struct {
	cfg      *config.Config
	fw       *bpf.Firewall
	state    *policy.State
	mu       sync.RWMutex
	stopCh   chan struct{}
	stopOnce sync.Once
}

func New(cfg *config.Config) (*Engine, error) {
	iface := cfg.Iface
	if iface == "" {
		var err error
		iface, err = bpf.DefaultInterface()
		if err != nil {
			return nil, err
		}
		cfg.Iface = iface
	}

	st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
	if err != nil {
		return nil, err
	}

	fw, err := bpf.NewFirewall(iface)
	if err != nil {
		return nil, err
	}

	if err := policy.ApplyMaps(fw.Objects(), st); err != nil {
		fw.Close()
		return nil, err
	}

	if err := fw.Attach(); err != nil {
		fw.Close()
		return nil, err
	}

	e := &Engine{cfg: cfg, fw: fw, state: st, stopCh: make(chan struct{})}
	log.Printf("firewall policy loaded: whitelist=%d blocklist=%d rules=%d iface=%s",
		len(st.Whitelist), len(st.Blocklist), len(st.Rules), cfg.Iface)
	go e.watchConfig()
	return e, nil
}

func (e *Engine) Reload() error {
	if err := policy.EnsureActiveSSHClientsAllow(e.cfg.AllowPath()); err != nil {
		return fmt.Errorf("ssh safety: %w", err)
	}
	st, err := policy.LoadState(e.cfg.AllowPath(), e.cfg.DenyPath(), e.cfg.PortsPath())
	if err != nil {
		return err
	}
	if err := policy.ApplyMaps(e.fw.Objects(), st); err != nil {
		return err
	}
	e.mu.Lock()
	e.state = st
	e.mu.Unlock()
	log.Printf("firewall policy reloaded: whitelist=%d blocklist=%d rules=%d iface=%s",
		len(st.Whitelist), len(st.Blocklist), len(st.Rules), e.cfg.Iface)
	return nil
}

func (e *Engine) State() *policy.State {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}

func (e *Engine) Firewall() *bpf.Firewall { return e.fw }
func (e *Engine) Config() *config.Config  { return e.cfg }

func (e *Engine) Close() error {
	e.stopOnce.Do(func() { close(e.stopCh) })
	return e.fw.Close()
}

func (e *Engine) watchConfig() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("config watcher: %v", err)
		return
	}
	defer watcher.Close()

	dir := e.cfg.ConfigDir
	if err := watcher.Add(dir); err != nil {
		log.Printf("config watcher add %s: %v", dir, err)
		return
	}

	var debounce *time.Timer
	reload := func() {
		if debounce != nil {
			debounce.Stop()
		}
		debounce = time.AfterFunc(500*time.Millisecond, func() {
			if err := e.Reload(); err != nil {
				log.Printf("config reload failed: %v", err)
			}
		})
	}

	for {
		select {
		case <-e.stopCh:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			base := filepath.Base(event.Name)
			switch base {
			case "firewall.allow", "firewall.deny", "ports.conf":
				reload()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("config watcher error: %v", err)
		}
	}
}

func (e *Engine) Stats() (bpf.Stats, error) {
	return e.fw.Stats()
}

func (e *Engine) Health() map[string]any {
	m := map[string]any{
		"status":    "ok",
		"iface":     e.cfg.Iface,
		"attached":  e.fw != nil,
		"configDir": e.cfg.ConfigDir,
	}
	if st := e.State(); st != nil {
		m["policy"] = st.Counts()
	}
	if s, err := e.Stats(); err == nil {
		m["stats"] = map[string]any{
			"xdp": map[string]uint64{"pass": s.XDPPass, "drop": s.XDPDrop},
			"tc":  map[string]uint64{"pass": s.TCPass, "drop": s.TCDrop},
		}
	}
	return m
}

func CopyExampleConfig(dst, example string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(example)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

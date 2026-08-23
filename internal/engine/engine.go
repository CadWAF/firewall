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
	"github.com/huzenkon/waf-firewall/internal/diag"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

type Engine struct {
	cfg       *config.Config
	fw        *bpf.Firewall
	state     *policy.State
	mu        sync.RWMutex
	reloadMu  sync.Mutex
	stopCh    chan struct{}
	stopOnce  sync.Once
	startedAt time.Time
	lastSnap  diag.Snapshot
	lastStats bpf.Stats
}

func New(cfg *config.Config) (*Engine, error) {
	// Always resolve via default-route + virtual-iface guards. Never pick the
	// first net.Interface (often docker0/br-* on waf-filter hosts) — that
	// attaches XDP to the Docker bridge and drops container userspace traffic.
	iface, err := cfg.ResolveAttachIface()
	if err != nil {
		return nil, err
	}
	cfg.Iface = iface

	st, err := policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
	if err != nil {
		return nil, err
	}

	// Normalize ports.conf on first start (inject SSH/QUIC if missing).
	e := &Engine{cfg: cfg, state: st, stopCh: make(chan struct{}), startedAt: time.Now()}
	if err := e.normalizeAndSavePorts(); err != nil {
		return nil, err
	}
	st, err = policy.LoadState(cfg.AllowPath(), cfg.DenyPath(), cfg.PortsPath())
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

	e.fw = fw
	e.state = st
	log.Printf("firewall policy loaded: whitelist=%d blocklist=%d rules=%d iface=%s",
		len(st.Whitelist), len(st.Blocklist), len(st.Rules), cfg.Iface)
	e.logSnapshot(diag.EventStartup, "engine_start")
	go e.watchConfig()
	go e.periodicDiag()
	go e.periodicMapRefresh()
	return e, nil
}

func (e *Engine) loadedPorts() *config.PortsConfig {
	pc, err := config.LoadPorts(e.cfg.PortsPath())
	if err != nil {
		return &config.PortsConfig{}
	}
	return pc
}

func (e *Engine) normalizeAndSavePorts() error {
	pc, err := config.LoadPorts(e.cfg.PortsPath())
	if err != nil {
		return err
	}
	beforeTCP := append([]uint16(nil), pc.TCPIn...)
	beforeUDP := append([]uint16(nil), pc.UDPIn...)
	policy.EnsureSafePorts(pc)
	if portsEqual(beforeTCP, pc.TCPIn) && portsEqual(beforeUDP, pc.UDPIn) {
		return nil
	}
	return config.SavePorts(e.cfg.PortsPath(), pc)
}

func portsEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (e *Engine) Reload() error {
	// reloadMu serializes every trigger: fsnotify, the 12h map-refresh
	// timer, the 15m integrity self-heal, the HTTP API, and SIGHUP. If one
	// call ever hangs (e.g. a stuck subprocess), it blocks all of those
	// silently — including the two self-healing paths that exist
	// specifically to recover from "config says X but BPF maps say Y"
	// drift. TryLock first so contention shows up in fw-diag instead of
	// just going quiet.
	if !e.reloadMu.TryLock() {
		diag.Log(diag.EventReloadStart, "trigger=reload status=waiting_lock note=previous_reload_still_running")
		e.reloadMu.Lock()
	}
	defer e.reloadMu.Unlock()

	diag.Log(diag.EventReloadStart, "trigger=reload")

	if err := policy.EnsureSSHSafety(e.cfg.AllowPath(), e.cfg.DenyPath(), e.cfg.PortsPath()); err != nil {
		diag.Log(diag.EventReloadFail, "stage=ssh_safety err="+err.Error())
		return fmt.Errorf("ssh safety: %w", err)
	}
	if err := e.normalizeAndSavePorts(); err != nil {
		diag.Log(diag.EventReloadFail, "stage=normalize_ports err="+err.Error())
		return err
	}

	newSt, err := policy.LoadState(e.cfg.AllowPath(), e.cfg.DenyPath(), e.cfg.PortsPath())
	if err != nil {
		diag.Log(diag.EventReloadFail, "stage=load_state err="+err.Error())
		return err
	}
	if err := policy.ValidateSSHReachable(e.cfg.AllowPath(), newSt.Ports); err != nil {
		diag.Log(diag.EventReloadFail, "stage=validate_ssh err="+err.Error())
		return err
	}

	e.mu.RLock()
	oldSt := e.state
	e.mu.RUnlock()

	if err := policy.ApplyMaps(e.fw.Objects(), newSt); err != nil {
		if oldSt != nil {
			if rbErr := policy.ApplyMaps(e.fw.Objects(), oldSt); rbErr != nil {
				diag.Log(diag.EventRollbackFail, "apply_err="+err.Error()+" rollback_err="+rbErr.Error())
				log.Printf("CRITICAL: reload failed (%v) and rollback failed (%v)", err, rbErr)
			} else {
				diag.Log(diag.EventRollbackOK, "apply_err="+err.Error())
				log.Printf("reload failed, restored previous policy: %v", err)
			}
		} else {
			diag.Log(diag.EventReloadFail, "stage=apply_maps err="+err.Error()+" rollback=skipped_no_old_state")
		}
		return err
	}

	e.mu.Lock()
	e.state = newSt
	e.mu.Unlock()
	log.Printf("firewall policy reloaded: whitelist=%d blocklist=%d rules=%d iface=%s",
		len(newSt.Whitelist), len(newSt.Blocklist), len(newSt.Rules), e.cfg.Iface)
	e.logSnapshot(diag.EventReloadOK, "reload")
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
				diag.Log(diag.EventReloadFail, "trigger=fsnotify err="+err.Error())
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
				diag.Log(diag.EventConfigChange, "file="+base+" op="+event.Op.String())
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
	if e.fw == nil {
		// No BPF attached (NewTestEngine, or Health() called during a
		// narrow window before New() finishes). The Linux loader's
		// Stats() dereferences the receiver immediately, so this must be
		// checked here rather than left to the caller.
		return bpf.Stats{}, nil
	}
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
	if e.fw != nil {
		if mc, err := policy.CountMaps(e.fw.Objects()); err == nil {
			m["maps"] = mc
		}
		if st := e.State(); st != nil && e.fw.Objects() != nil {
			integrity := map[string]any{}
			if st.Ports != nil {
				missing, err := policy.VerifyPortMapKeys(e.fw.Objects().TcpInPorts, st.Ports.TCPIn)
				if err != nil {
					integrity["tcp_in_err"] = err.Error()
				} else if len(missing) > 0 {
					integrity["tcp_in_missing"] = missing
					m["status"] = "degraded"
				}
			}
			missingWL, err := policy.VerifyWhitelistV4Keys(e.fw.Objects().WhitelistV4, st.Whitelist)
			if err != nil {
				integrity["whitelist_err"] = err.Error()
			} else if len(missingWL) > 0 {
				integrity["whitelist_missing"] = missingWL
				m["status"] = "degraded"
			}
			if len(integrity) > 0 {
				m["map_integrity"] = integrity
			}
		}
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

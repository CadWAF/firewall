package diag

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Event kinds — grep journal with: journalctl -u firewalld | grep 'fw-diag'
const (
	EventStartup      = "startup"
	EventPeriodic     = "periodic"
	EventReloadStart  = "reload_start"
	EventReloadOK     = "reload_ok"
	EventReloadFail   = "reload_fail"
	EventRollbackOK   = "rollback_ok"
	EventRollbackFail = "rollback_fail"
	EventConfigChange = "config_change"
	EventAlert        = "alert"
	EventMapRefresh   = "map_refresh"
)

var (
	mu      sync.Mutex
	writers []io.Writer
	std     = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
)

// Init configures optional file logging from FIREWALL_DIAG_LOG.
func Init() {
	path := os.Getenv("FIREWALL_DIAG_LOG")
	if path == "" {
		path = "/var/log/firewalld-diag.log"
	}
	if os.Getenv("FIREWALL_DIAG_LOG") == "off" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		std.Printf("fw-diag: cannot open log file %s: %v (journal only)", path, err)
		return
	}
	mu.Lock()
	writers = append(writers, f)
	mu.Unlock()
	std.Printf("fw-diag: file logging enabled path=%s", path)
}

// Interval returns how often to emit periodic snapshots.
func Interval() time.Duration {
	if v := os.Getenv("FIREWALL_DIAG_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			return d
		}
	}
	return 15 * time.Minute
}

// MapRefreshInterval returns how often to re-apply BPF map contents from disk
// without detaching XDP/TC. Default 12h. Set FIREWALL_MAP_REFRESH_INTERVAL=off
// (or 0) to disable.
func MapRefreshInterval() time.Duration {
	v := strings.TrimSpace(os.Getenv("FIREWALL_MAP_REFRESH_INTERVAL"))
	if v == "" {
		return 12 * time.Hour
	}
	if v == "off" || v == "0" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute {
		return 12 * time.Hour
	}
	return d
}

// Snapshot holds a point-in-time firewall diagnostic record.
type Snapshot struct {
	UptimeSec      int64
	Iface          string
	Trigger        string
	WhitelistN     int
	BlocklistN     int
	RulesN         int
	TCPInN         int
	UDPInN         int
	TCPOutN        int
	UDPOutN        int
	MapWhitelistV4 int
	MapWhitelistV6 int
	MapBlocklistV4 int
	MapBlocklistV6 int
	MapTCPIn       int
	WhitelistIPs   []string
	XDPPass        uint64
	XDPDrop        uint64
	TCPass         uint64
	TCDrop         uint64
	XDPDropDelta   uint64
	TCDropDelta    uint64
	Extra          string
}

func (s Snapshot) format() string {
	return fmt.Sprintf(
		"uptime=%ds iface=%s wl=%d bl=%d rules=%d tcp_in=%d udp_in=%d tcp_out=%d udp_out=%d map_wl_v4=%d map_wl_v6=%d map_bl_v4=%d map_bl_v6=%d map_tcp_in=%d xdp_pass=%d xdp_drop=%d xdp_drop_delta=%d tc_pass=%d tc_drop=%d tc_drop_delta=%d wl_ips=%q %s",
		s.UptimeSec, s.Iface,
		s.WhitelistN, s.BlocklistN, s.RulesN,
		s.TCPInN, s.UDPInN, s.TCPOutN, s.UDPOutN,
		s.MapWhitelistV4, s.MapWhitelistV6, s.MapBlocklistV4, s.MapBlocklistV6, s.MapTCPIn,
		s.XDPPass, s.XDPDrop, s.XDPDropDelta,
		s.TCPass, s.TCDrop, s.TCDropDelta,
		s.WhitelistIPs, s.Extra,
	)
}

// Log writes a structured diagnostic line.
func Log(event, detail string) {
	line := fmt.Sprintf("fw-diag event=%s %s", event, detail)
	std.Println(line)
	mu.Lock()
	defer mu.Unlock()
	for _, w := range writers {
		fmt.Fprintln(w, time.Now().Format(time.RFC3339Nano), line)
	}
}

// LogSnapshot emits a periodic or event snapshot.
func LogSnapshot(event string, s Snapshot) {
	Log(event, s.format())
}

// CheckAlerts logs alert events for suspicious policy/stats changes.
func CheckAlerts(prev, cur Snapshot) {
	mapWL := cur.MapWhitelistV4 + cur.MapWhitelistV6
	mapBL := cur.MapBlocklistV4 + cur.MapBlocklistV6

	if cur.WhitelistN == 0 && cur.TCPInN == 0 {
		Log(EventAlert, "whitelist_empty policy has zero allow IPs and zero tcp_in ports — inbound traffic may be fully blocked")
	}
	if prev.WhitelistN > 0 && cur.WhitelistN == 0 {
		Log(EventAlert, fmt.Sprintf("whitelist_cleared was=%d now=0", prev.WhitelistN))
	}
	if cur.WhitelistN > 0 && mapWL == 0 {
		Log(EventAlert, fmt.Sprintf("bpf_whitelist_empty config_wl=%d but map_wl_v4+v6=0 — reload may have failed mid-apply", cur.WhitelistN))
	}
	if cur.WhitelistN > 0 && mapWL > 0 && mapWL < cur.WhitelistN {
		Log(EventAlert, fmt.Sprintf("bpf_whitelist_partial config_wl=%d map_wl_v4=%d map_wl_v6=%d", cur.WhitelistN, cur.MapWhitelistV4, cur.MapWhitelistV6))
	}
	if cur.BlocklistN > 0 && mapBL == 0 {
		Log(EventAlert, fmt.Sprintf("bpf_blocklist_empty config_bl=%d but map_bl_v4+v6=0", cur.BlocklistN))
	}
	if cur.TCPInN > 0 && cur.MapTCPIn == 0 {
		Log(EventAlert, fmt.Sprintf("bpf_tcp_in_empty config_tcp_in=%d but map_tcp_in=0 — new inbound TCP may be blocked", cur.TCPInN))
	}
	if cur.TCPInN > 0 && cur.MapTCPIn > 0 && cur.MapTCPIn < cur.TCPInN {
		Log(EventAlert, fmt.Sprintf("bpf_tcp_in_partial config_tcp_in=%d map_tcp_in=%d", cur.TCPInN, cur.MapTCPIn))
	}
	// >10k XDP drops per interval suggests sudden blackout or attack
	if cur.XDPDropDelta > 10000 {
		Log(EventAlert, fmt.Sprintf("xdp_drop_spike delta=%d total=%d", cur.XDPDropDelta, cur.XDPDrop))
	}
	if cur.TCDropDelta > 10000 {
		Log(EventAlert, fmt.Sprintf("tc_drop_spike delta=%d total=%d", cur.TCDropDelta, cur.TCDrop))
	}
}

package engine

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/huzenkon/waf-firewall/internal/bpf"
	"github.com/huzenkon/waf-firewall/internal/diag"
	"github.com/huzenkon/waf-firewall/internal/policy"
)

func (e *Engine) startTime() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.startedAt.IsZero() {
		return time.Now()
	}
	return e.startedAt
}

func (e *Engine) buildSnapshot(trigger string, prevStats bpf.Stats) diag.Snapshot {
	st := e.State()
	s := diag.Snapshot{
		UptimeSec: int64(time.Since(e.startTime()).Seconds()),
		Iface:     e.cfg.Iface,
		Trigger:   trigger,
	}
	if st != nil {
		c := st.Counts()
		s.WhitelistN = c.Whitelist
		s.BlocklistN = c.Blocklist
		s.RulesN = c.Rules
		s.TCPInN = c.TCPIn
		s.UDPInN = c.UDPIn
		s.TCPOutN = c.TCPOut
		s.UDPOutN = c.UDPOut
		s.WhitelistIPs = append([]string(nil), st.Whitelist...)
	}
	if e.fw != nil {
		if mc, err := policy.CountMaps(e.fw.Objects()); err == nil {
			s.MapWhitelistV4 = mc.WhitelistV4
			s.MapWhitelistV6 = mc.WhitelistV6
			s.MapBlocklistV4 = mc.BlocklistV4
			s.MapBlocklistV6 = mc.BlocklistV6
			s.MapTCPIn = mc.TCPIn
		}
		if cur, err := e.fw.Stats(); err == nil {
			s.XDPPass = cur.XDPPass
			s.XDPDrop = cur.XDPDrop
			s.TCPass = cur.TCPass
			s.TCDrop = cur.TCDrop
			if cur.XDPDrop >= prevStats.XDPDrop {
				s.XDPDropDelta = cur.XDPDrop - prevStats.XDPDrop
			}
			if cur.TCDrop >= prevStats.TCDrop {
				s.TCDropDelta = cur.TCDrop - prevStats.TCDrop
			}
		}
	}
	return s
}

func (e *Engine) logSnapshot(event, trigger string) {
	prev := e.lastStats
	s := e.buildSnapshot(trigger, prev)
	if event == diag.EventPeriodic {
		diag.CheckAlerts(e.lastSnap, s)
		e.checkMapKeyIntegrity()
	}
	diag.LogSnapshot(event, s)
	e.mu.Lock()
	e.lastSnap = s
	if e.fw != nil {
		if cur, err := e.fw.Stats(); err == nil {
			e.lastStats = cur
		}
	}
	e.mu.Unlock()
}

// checkMapKeyIntegrity verifies configured ports/IPs are actually lookupable in
// BPF maps (not just that entry counts match). Catches false-drop outages where
// tcp_in=2 and map_tcp_in=2 but keys are not 80/443, or whitelist IPs missing.
func (e *Engine) checkMapKeyIntegrity() {
	st := e.State()
	if st == nil || e.fw == nil {
		return
	}
	objs := e.fw.Objects()
	if objs == nil {
		return
	}
	if st.Ports != nil {
		portChecks := []struct {
			name    string
			m       *ebpf.Map
			want    []uint16
			trigger string
		}{
			{"tcp_in", objs.TcpInPorts, st.Ports.TCPIn, "integrity_tcp_in"},
			{"udp_in", objs.UdpInPorts, st.Ports.UDPIn, "integrity_udp_in"},
			{"tcp_out", objs.TcpOutPorts, st.Ports.TCPOut, "integrity_tcp_out"},
			{"udp_out", objs.UdpOutPorts, st.Ports.UDPOut, "integrity_udp_out"},
		}
		for _, c := range portChecks {
			missing, err := policy.VerifyPortMapKeys(c.m, c.want)
			if err != nil {
				diag.Log(diag.EventAlert, fmt.Sprintf("bpf_%s_lookup_err err=%s", c.name, err.Error()))
				continue
			}
			if len(missing) > 0 {
				diag.Log(diag.EventAlert, fmt.Sprintf(
					"bpf_%s_keys_missing config_ports=%v missing_in_map=%v — traffic on these ports is XDP_DROP/TC_ACT_SHOT",
					c.name, c.want, missing,
				))
				go e.RefreshMaps(c.trigger)
			}
		}
	}
	missingWL, err := policy.VerifyWhitelistV4Keys(objs.WhitelistV4, st.Whitelist)
	if err != nil {
		diag.Log(diag.EventAlert, "bpf_whitelist_lookup_err err="+err.Error())
	} else if len(missingWL) > 0 {
		diag.Log(diag.EventAlert, fmt.Sprintf(
			"bpf_whitelist_keys_missing missing_in_map=%v — allow-list IPs are not matching XDP lookups",
			missingWL,
		))
		go e.RefreshMaps("integrity_whitelist")
	}
	missingWL6, err := policy.VerifyWhitelistV6Keys(objs.WhitelistV6, st.Whitelist)
	if err != nil {
		diag.Log(diag.EventAlert, "bpf_whitelist_v6_lookup_err err="+err.Error())
	} else if len(missingWL6) > 0 {
		diag.Log(diag.EventAlert, fmt.Sprintf(
			"bpf_whitelist_v6_keys_missing missing_in_map=%v — allow-list IPv6s are not matching XDP lookups",
			missingWL6,
		))
		go e.RefreshMaps("integrity_whitelist_v6")
	}
}

func (e *Engine) periodicDiag() {
	interval := diag.Interval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	diag.Log("diag_loop", "interval="+interval.String())

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.logSnapshot(diag.EventPeriodic, "ticker")
		}
	}
}

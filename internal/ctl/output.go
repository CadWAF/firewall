package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/huzenkon/waf-firewall/internal/policy"
)

// PacketStat is ingress/egress pass-drop counters from BPF maps.
type PacketStat struct {
	Pass uint64 `json:"pass"`
	Drop uint64 `json:"drop"`
}

// PacketStats holds XDP and TC counters.
type PacketStats struct {
	XDP PacketStat `json:"xdp"`
	TC  PacketStat `json:"tc"`
}

// StatInfo is packet counter snapshot from the running daemon.
type StatInfo struct {
	Active bool        `json:"active"`
	Stats  PacketStats `json:"stats"`
}

func (s StatInfo) FormatText() string {
	if !s.Active {
		return "firewalld is not running\n"
	}
	return fmt.Sprintf("xdp pass=%d drop=%d\ntc pass=%d drop=%d\n",
		s.Stats.XDP.Pass, s.Stats.XDP.Drop, s.Stats.TC.Pass, s.Stats.TC.Drop)
}

// StatusInfo is service and policy snapshot.
type StatusInfo struct {
	Service      string        `json:"service"`
	Interface    string        `json:"interface"`
	API          string        `json:"api,omitempty"`
	Policy       policy.Counts `json:"policy"`
	PolicySource string        `json:"policy_source"`
}

func (s StatusInfo) FormatText() string {
	var b string
	b += fmt.Sprintf("service: %s\ninterface: %s\n", s.Service, s.Interface)
	if s.API != "" {
		b += fmt.Sprintf("api: %s\n", s.API)
	}
	b += fmt.Sprintf("policy (%s): %s\n", s.PolicySource, s.Policy)
	return b
}

// ListResult is allow/block IP lists from config files.
type ListResult struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}

func (l ListResult) FormatText() string {
	return formatIPList("allow", l.Allow) + formatIPList("block", l.Block)
}

func formatIPList(name string, ips []string) string {
	var b string
	b += fmt.Sprintf("[%s]\n", name)
	if len(ips) == 0 {
		b += "  (empty)\n"
		return b
	}
	for _, ip := range ips {
		b += fmt.Sprintf("  %s\n", ip)
	}
	return b
}

// IPChangeResult is the outcome of allow/block/unallow/unblock.
type IPChangeResult struct {
	Action string `json:"action"`
	IP     string `json:"ip"`
	ApplyResult
}

func (r IPChangeResult) FormatText() string {
	return fmt.Sprintf("%s %s\n%s", r.Action, r.IP, r.ApplyResult.FormatText())
}

// OKResult is a generic success response.
type OKResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func (r OKResult) FormatText() string {
	if r.Message != "" {
		return r.Message + "\n"
	}
	return "ok\n"
}

// Emit writes a command result as text or JSON.
func Emit(jsonOut bool, w io.Writer, v any) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if f, ok := v.(textFormatter); ok {
		_, err := io.WriteString(w, f.FormatText())
		return err
	}
	_, err := fmt.Fprintf(w, "%v\n", v)
	return err
}

// EmitStdout is a convenience wrapper for Emit(os.Stdout).
func EmitStdout(jsonOut bool, v any) error {
	return Emit(jsonOut, os.Stdout, v)
}

type textFormatter interface {
	FormatText() string
}

// ParseArgs removes global flags and returns the remaining command arguments.
func ParseArgs(args []string) (jsonOut bool, cmdArgs []string) {
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
			continue
		}
		cmdArgs = append(cmdArgs, a)
	}
	return jsonOut, cmdArgs
}

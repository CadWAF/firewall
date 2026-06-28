package main

import (
	"fmt"
	"os"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/ctl"
)

func main() {
	jsonOut, args := ctl.ParseArgs(os.Args[1:])
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}

	cfg, err := config.LoadCLI()
	if err != nil {
		fail(jsonOut, err)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	var emitErr error
	switch cmd {
	case "allow":
		emitErr = runIPChange(jsonOut, cfg, cmdArgs, ctl.AllowIP)
	case "block", "deny":
		emitErr = runIPChange(jsonOut, cfg, cmdArgs, ctl.BlockIP)
	case "unallow", "del-allow", "remove-allow":
		emitErr = runIPChange(jsonOut, cfg, cmdArgs, ctl.UnallowIP)
	case "unblock", "del-block", "remove-block", "undeny":
		emitErr = runIPChange(jsonOut, cfg, cmdArgs, ctl.UnblockIP)
	case "activate", "start", "on":
		emitErr = runOK(jsonOut, ctl.Activate(cfg))
	case "deactivate", "stop", "off":
		emitErr = runOK(jsonOut, ctl.Deactivate(cfg))
	case "reactivate", "restart":
		emitErr = runOK(jsonOut, ctl.Reactivate(cfg))
	case "reload":
		result, err := ctl.Reload(cfg)
		emitErr = emitResult(jsonOut, result, err)
	case "hooks-off":
		emitErr = runOK(jsonOut, ctl.HooksOff(cfg))
	case "ls", "list":
		emitErr = runList(jsonOut, cfg, cmdArgs)
	case "status":
		info, err := ctl.Status(cfg)
		emitErr = emitResult(jsonOut, info, err)
	case "stat", "stats":
		info, err := ctl.Stat(cfg)
		emitErr = emitResult(jsonOut, info, err)
	case "help", "-h", "--help":
		usage()
		return
	default:
		if !jsonOut {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
			usage()
		} else {
			_ = ctl.EmitStdout(true, map[string]string{"error": "unknown command: " + cmd})
		}
		os.Exit(2)
	}

	if emitErr != nil {
		fail(jsonOut, emitErr)
	}
}

type ipChangeFn func(*config.Config, string) (ctl.IPChangeResult, error)

func runIPChange(jsonOut bool, cfg *config.Config, args []string, fn ipChangeFn) error {
	if len(args) != 1 {
		return fmt.Errorf("IP address required")
	}
	result, err := fn(cfg, args[0])
	return emitResult(jsonOut, result, err)
}

func runList(jsonOut bool, cfg *config.Config, args []string) error {
	which := "all"
	if len(args) > 0 {
		which = args[0]
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: firewallctl ls [allow|block]")
	}
	result, err := ctl.ListIPs(cfg, which)
	return emitResult(jsonOut, result, err)
}

func runOK(jsonOut bool, err error) error {
	if err != nil {
		return err
	}
	return ctl.EmitStdout(jsonOut, ctl.OKResult{OK: true})
}

func emitResult(jsonOut bool, v any, err error) error {
	if err != nil {
		return err
	}
	return ctl.EmitStdout(jsonOut, v)
}

func fail(jsonOut bool, err error) {
	if jsonOut {
		_ = ctl.Emit(true, os.Stderr, map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `firewallctl — manage WAF host firewall
Alias: firewalldctl

Usage:
  firewallctl [--json] <command> [args]

Global flags:
  --json                  Output JSON instead of plain text

IP management:
  allow <ip>              Add IP to whitelist (firewall.allow)
  block <ip>              Add IP to blocklist (firewall.deny)
  unallow <ip>            Remove IP from whitelist
  unblock <ip>            Remove IP from blocklist
  ls [allow|block]        List whitelisted and/or blocked IPs

Service control:
  activate                Start firewalld (enable filtering)
  deactivate              Stop firewalld and detach XDP/TC hooks
  reactivate              Deactivate then activate
  reload                  Apply firewall.allow, firewall.deny, ports.conf to BPF
  hooks-off               Detach XDP/TC hooks only (used by systemd)

Other:
  status                  Show service and policy counts
  stat                    Show packet pass/drop counters from memory

Config: /etc/firewall/firewalld.env
`)
}

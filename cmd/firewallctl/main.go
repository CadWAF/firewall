package main

import (
	"fmt"
	"os"

	"github.com/huzenkon/waf-firewall/internal/config"
	"github.com/huzenkon/waf-firewall/internal/ctl"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cfg, err := config.LoadCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	var runErr error
	switch os.Args[1] {
	case "allow":
		runErr = needArg(runAllow, cfg, os.Args[2:])
	case "block", "deny":
		runErr = needArg(runBlock, cfg, os.Args[2:])
	case "unallow", "del-allow", "remove-allow":
		runErr = needArg(runUnallow, cfg, os.Args[2:])
	case "unblock", "del-block", "remove-block", "undeny":
		runErr = needArg(runUnblock, cfg, os.Args[2:])
	case "activate", "start", "on":
		runErr = ctl.Activate()
	case "deactivate", "stop", "off":
		runErr = ctl.Deactivate(cfg)
	case "reactivate", "restart":
		runErr = ctl.Reactivate(cfg)
	case "hooks-off":
		runErr = ctl.HooksOff(cfg)
	case "ls", "list":
		runErr = runList(cfg, os.Args[2:])
	case "status":
		var out string
		out, runErr = ctl.Status(cfg)
		if runErr == nil {
			fmt.Print(out)
		}
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", runErr)
		os.Exit(1)
	}
}

type ipFn func(*config.Config, string) error

func needArg(fn ipFn, cfg *config.Config, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("IP address required")
	}
	return fn(cfg, args[0])
}

func runAllow(cfg *config.Config, ip string) error {
	if err := ctl.AllowIP(cfg, ip); err != nil {
		return err
	}
	fmt.Printf("allowed %s\n", ip)
	return nil
}

func runBlock(cfg *config.Config, ip string) error {
	if err := ctl.BlockIP(cfg, ip); err != nil {
		return err
	}
	fmt.Printf("blocked %s\n", ip)
	return nil
}

func runUnallow(cfg *config.Config, ip string) error {
	if err := ctl.UnallowIP(cfg, ip); err != nil {
		return err
	}
	fmt.Printf("removed %s from allow list\n", ip)
	return nil
}

func runUnblock(cfg *config.Config, ip string) error {
	if err := ctl.UnblockIP(cfg, ip); err != nil {
		return err
	}
	fmt.Printf("removed %s from block list\n", ip)
	return nil
}

func runList(cfg *config.Config, args []string) error {
	which := "all"
	if len(args) > 0 {
		which = args[0]
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: firewallctl ls [allow|block]")
	}

	allow, block, err := ctl.ListIPs(cfg)
	if err != nil {
		return err
	}

	switch which {
	case "all", "":
		printIPList("allow", allow)
		printIPList("block", block)
	case "allow", "whitelist", "white":
		printIPList("allow", allow)
	case "block", "deny", "blacklist", "black":
		printIPList("block", block)
	default:
		return fmt.Errorf("unknown list: %s (use allow or block)", which)
	}
	return nil
}

func printIPList(name string, ips []string) {
	fmt.Printf("[%s]\n", name)
	if len(ips) == 0 {
		fmt.Println("  (empty)")
		return
	}
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `firewallctl — manage WAF host firewall
Alias: firewalldctl

Usage:
  firewallctl <command> [args]

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
  hooks-off               Detach XDP/TC hooks only (used by systemd)

Other:
  status                  Show service and interface status

Config: /etc/firewall/firewalld.env
`)
}

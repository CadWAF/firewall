# WAF Host Firewall

CSF-like host-level firewall using **eBPF + XDP** (ingress) and **TC egress** (outbound). All traffic is filtered at the kernel before reaching services.

## Features

- Strict default-deny inbound and outbound
- IP whitelist (bypass all rules) and blocklist
- Port allow lists for inbound and outbound traffic
- CSF-compatible complex rules in `firewall.allow` / `firewall.deny`
- Hot reload via config file watcher
- REST API for integrations (`docs/API.md`)

## Quick install (new Linux server)

From the WAF repo root:

```bash
sudo ./scripts/setup-firewall.sh
```

Requires root, Linux kernel ≥ 5.10, `clang`, and `llvm`.

## Manual build

```bash
cd firewall
make generate   # bpf2go (requires clang with bpf target)
make build      # produces bin/firewalld
sudo make install
```

## Configuration

| File | Description |
|------|-------------|
| `firewall.allow` | Whitelisted IPs (one per line) + complex allow rules |
| `firewall.deny` | Blocked IPs + complex deny rules |
| `ports.conf` | `tcp_in`, `udp_in`, `tcp_out`, `udp_out` |
| `firewalld.env` | `FIREWALL_API_TOKEN`, `FIREWALL_IFACE`, `FIREWALL_LISTEN_ADDR` |

## Architecture

```
Internet → XDP (ingress) → kernel stack → services
services → TC egress → Internet
```

Runs on the **host** beneath Docker/Caddy. Attach to the physical NIC (`eth0`, `ens*`), not `docker0`.

## systemd

```bash
sudo systemctl enable --now firewalld
sudo systemctl status firewalld
```

Environment: `/etc/firewall/firewalld.env`

## Development

```bash
cd firewall
go test ./...
```

BPF code generation requires clang with `bpfel` target (LLVM). On macOS: `brew install llvm`.

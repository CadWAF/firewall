# WAF Host Firewall

CSF-like host-level firewall using **eBPF + XDP** (ingress) and **TC egress** (outbound). All traffic is filtered at the kernel before reaching services.

This is an **optional** layer beneath Docker/Caddy — independent of [waf-filter](https://github.com/Revabrio/waf-filter) and [admin-panel](https://github.com/Revabrio/admin-panel).

## Features

- Strict default-deny inbound and outbound
- IP whitelist (bypass all rules) and blocklist
- Port allow lists for inbound and outbound traffic
- CSF-compatible complex rules in `firewall.allow` / `firewall.deny`
- Hot reload via config file watcher
- REST API for integrations ([`docs/API.md`](docs/API.md))
- CLI via `firewallctl`

## Architecture

```
Internet → XDP (ingress) → kernel stack → services
services → TC egress → Internet
```

Attach to the **physical NIC** (`eth0`, `ens*`), not `docker0`. Runs on the host beneath Docker/Caddy.

## Requirements

| Requirement | Notes |
|-------------|-------|
| **OS** | Linux only |
| **Kernel** | ≥ 5.10 |
| **Build** | clang, llvm, libbpf-dev, linux-headers, Go 1.23+, make |
| **Runtime** | systemd, iproute2 (`ip`, `tc`), root/CAP_BPF |

## Quick install (production)

```bash
git clone https://github.com/Revabrio/firewall.git
cd firewall
sudo ./scripts/setup-firewall.sh
```

The script installs dependencies, builds `firewalld`, creates `/etc/firewall/firewalld.env` with a random API token, whitelists your SSH IP, and enables the systemd unit.

**Important:** Keep a second SSH session open when starting the firewall for the first time. Use the emergency recovery script if locked out (see below).

## Manual build and install

```bash
cd firewall
make generate   # bpf2go (requires clang with bpf target)
make build      # produces bin/firewalld and bin/firewallctl
sudo make install
```

## Configuration

Files live under `/etc/firewall/` (created by `make install`):

| File | Description |
|------|-------------|
| `firewall.allow` | Whitelisted IPs (one per line) + complex allow rules |
| `firewall.deny` | Blocked IPs + complex deny rules |
| `ports.conf` | `tcp_in`, `udp_in`, `tcp_out`, `udp_out`, `allow_localhost` |
| `firewalld.env` | `FIREWALL_API_TOKEN`, `FIREWALL_IFACE`, `FIREWALL_LISTEN_ADDR` |

Example `ports.conf`:

Example `ports.conf` (ranges: `80-443` or CSF `2000_3000`):

```
tcp_in = 22,80-443,8080
udp_in = 53
tcp_out = 80-443,3306,8080,53
udp_out = 53,123
allow_localhost = true
```

Set `FIREWALL_EGRESS=false` in `firewalld.env` to disable outbound TC filtering (ingress XDP only).

## systemd

```bash
sudo systemctl enable --now firewalld
sudo systemctl status firewalld
curl http://127.0.0.1:9090/health
```

Environment file: `/etc/firewall/firewalld.env`

## CLI (`firewallctl`)

```bash
firewallctl allow 203.0.113.1
firewallctl block 198.51.100.0/24
firewallctl status
firewallctl reload
firewallctl hooks-off    # emergency: detach XDP/TC without stopping daemon
```

## REST API

Bearer auth via `FIREWALL_API_TOKEN`. Local bind default: `127.0.0.1:9090`.

```bash
curl -H "Authorization: Bearer ${FIREWALL_API_TOKEN}" http://127.0.0.1:9090/api/v1/ports
```

Full API reference: [`docs/API.md`](docs/API.md)

## Emergency recovery

If SSH is blocked by orphaned XDP/TC rules, run from your provider's console (VNC):

```bash
sudo ./scripts/firewall-emergency-recover.sh [interface]
```

Then whitelist your IP before re-enabling:

```bash
firewallctl allow <your-ip>
firewallctl activate
```

## Development

```bash
cd firewall
go test ./...
```

BPF code generation requires clang with `bpfel` target. On macOS (build only, no runtime): `brew install llvm`.

## Tests

```bash
make test
```

Unit tests cover rule parsing, policy loading, and IPv4 BPF key layout. No in-kernel integration tests in CI.

## CI and releases

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| **CI** | Push/PR to `dev` | bpf2go generate, build, `go test ./...` |
| **Release** | Tag `v*.*.*` | Linux amd64 + arm64 binary tarballs on GitHub Releases |

Release tarball includes: `firewalld`, `firewallctl`, example configs, `docs/API.md`.

## Related projects

| Project | Description |
|---------|-------------|
| [waf-filter](https://github.com/Revabrio/waf-filter) | WAF edge node (Caddy) |
| [admin-panel](https://github.com/Revabrio/admin-panel) | WAF control plane |

## License

MIT — see [LICENSE](LICENSE).

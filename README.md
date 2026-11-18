<div align="center">

# CadWAF Firewall

**A CSF-style host firewall for Linux, enforced in the kernel with eBPF/XDP.**
Default-deny inbound and outbound, IP allow/deny lists, per-port access control,
hot reload, a REST API and a CLI — filtering every packet before it reaches your
services.

![Version](https://img.shields.io/badge/version-0.3.0-success)
![Platform](https://img.shields.io/badge/platform-Linux-informational)
![Kernel](https://img.shields.io/badge/kernel-%E2%89%A5%205.10-informational)
![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)
[![CI](https://github.com/Revabrio/firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Revabrio/firewall/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)

</div>

---

## Contents

- [What it is](#what-it-is)
- [Where this fits — the CadWAF platform](#where-this-fits--the-cadwaf-platform)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Configuration](#configuration)
- [Running under systemd](#running-under-systemd)
- [Command line — `firewallctl`](#command-line--firewallctl)
- [REST API](#rest-api)
- [Diagnostics](#diagnostics)
- [Emergency recovery](#emergency-recovery)
- [Development](#development)
- [CI, testing and releases](#ci-testing-and-releases)
- [License](#license)

---

## What it is

`firewalld` is a small, self-contained daemon that attaches an **XDP** program to
your network interface for inbound filtering and a **TC** program for outbound,
so traffic is judged in the kernel — before the socket layer, before Docker,
before anything you run. It is deliberately CSF-like in feel: two text files for
allow/deny, one for ports, hot-reloaded on change.

It is an **optional, independent** layer. It has no dependency on the rest of the
CadWAF stack and is useful on any Linux host on its own.

**What it gives you**

- Strict **default-deny** inbound and outbound.
- An **IP allow list** (bypass all rules) and a **block list**.
- **Per-port** access control for inbound and outbound, with ranges.
- CSF-compatible complex rules in `firewall.allow` / `firewall.deny`.
- **Hot reload** via a config-file watcher — no traffic blackout on refresh.
- A **REST API** for integrations and a **`firewallctl`** CLI.
- Built-in **diagnostics** and a tested **emergency recovery** path.

---

## Where this fits — the CadWAF platform

CadWAF is a self-hosted WAF and DDoS-protection stack. Each component runs on its
own and they compose into a full edge:

| Component | Role |
|-----------|------|
| admin-panel *(private)* | Control plane — canonical config, users, analytics (Laravel + React) |
| waf-filter *(private)* | Autonomous edge node — Caddy + WAF / anti-DDoS plugins |
| balancer *(private)* | HAProxy in front of several edges, preserving the visitor's address |
| **firewall** *(this repo)* | Host-level eBPF/XDP packet firewall — default-deny, port ACLs |

> The other CadWAF components are **not publicly available** — this firewall is the only open repository. The rows above describe where it sits in the platform; the private components are not required to run it.

The firewall sits **beneath** everything else on a host. Run it on an edge node
under Caddy, or — when a balancer fronts
the cluster and the edges no longer see real client addresses — run it on the
balancer host, where packet-level filtering then belongs.

---

## How it works

```
Internet ──▶ XDP (ingress) ──▶ kernel stack ──▶ services
services  ──▶ TC  (egress)  ──▶ Internet
```

Attach to the **physical NIC** (`eth0`, `ens*`), never to `docker0` / `br-*` /
`veth*`. If `FIREWALL_IFACE` is unset the daemon selects the **default-route**
interface and **refuses** Docker bridges: attaching XDP to `br-*` silently drops
container-to-container traffic while the WAN still looks healthy — the classic
symptom being hourly veth/bridge churn in the kernel log.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **OS** | Linux only |
| **Kernel** | ≥ 5.10 |
| **Build** | clang, llvm, libbpf-dev, linux-headers, Go 1.23+, make |
| **Runtime** | systemd, iproute2 (`ip`, `tc`), root / `CAP_BPF` |

---

## Install

### Guided (recommended)

```bash
git clone https://github.com/Revabrio/firewall.git
cd firewall
sudo ./scripts/setup-firewall.sh
```

The script installs build dependencies, builds `firewalld`, writes
`/etc/firewall/firewalld.env` with a random API token, whitelists your current
SSH address, and enables the systemd unit.

> [!IMPORTANT]
> Keep a **second SSH session open** the first time you start the firewall. If a
> rule ever locks you out, use the [emergency recovery](#emergency-recovery)
> script from your provider's console.

### Manual build

```bash
cd firewall
make generate   # bpf2go — requires clang with the bpf target
make build      # produces bin/firewalld and bin/firewallctl
sudo make install
```

---

## Configuration

Configuration lives under `/etc/firewall/` (created by `make install`):

| File | Purpose |
|------|---------|
| `firewall.allow` | Whitelisted IPs (one per line) + complex allow rules |
| `firewall.deny` | Blocked IPs + complex deny rules |
| `ports.conf` | `tcp_in`, `udp_in`, `tcp_out`, `udp_out`, `allow_localhost` |
| `firewalld.env` | `FIREWALL_API_TOKEN`, `FIREWALL_IFACE`, `FIREWALL_LISTEN_ADDR` |

Example `ports.conf` (ranges: `80-443`, or CSF-style `2000_3000`):

```ini
tcp_in  = 22,80-443,8080
udp_in  = 443
tcp_out = 80-443,3306,8080,53
udp_out = 53,123
allow_localhost = true
```

Set `FIREWALL_EGRESS=false` in `firewalld.env` to disable outbound TC filtering
(ingress XDP only).

---

## Running under systemd

```bash
sudo systemctl enable --now firewalld
sudo systemctl status firewalld
curl http://127.0.0.1:9090/health
```

Environment file: `/etc/firewall/firewalld.env`.

---

## Command line — `firewallctl`

```bash
firewallctl allow 203.0.113.1
firewallctl block 198.51.100.0/24
firewallctl status
firewallctl reload
firewallctl hooks-off      # emergency: detach XDP/TC (stops the service; see recovery)
```

---

## REST API

Bearer auth via `FIREWALL_API_TOKEN`. Local bind defaults to `127.0.0.1:9090`.

```bash
curl -H "Authorization: Bearer ${FIREWALL_API_TOKEN}" \
     http://127.0.0.1:9090/api/v1/ports
```

Full reference: [`docs/API.md`](docs/API.md).

---

## Diagnostics

`firewalld` writes structured lines prefixed with **`fw-diag`** to journald and,
by default, to `/var/log/firewalld-diag.log`. Configure in `firewalld.env`:

```bash
FIREWALL_DIAG_LOG=/var/log/firewalld-diag.log   # or "off"
FIREWALL_DIAG_INTERVAL=15m                       # periodic snapshot
FIREWALL_MAP_REFRESH_INTERVAL=12h                # re-sync BPF maps in place ("off" to disable)
```

- **Every 15 minutes** (default): policy counts, whitelist IPs, BPF map sizes
  (v4 + v6), `tcp_in` map size, XDP/TC pass/drop totals and deltas — and it
  verifies that configured ports/IPs are actually **lookupable** in the maps, not
  merely counted.
- **Every 12 hours** (default): re-reads the config and `ApplyMaps` into the
  **same** attached XDP/TC programs — no hook detach, no blackout. Runs
  immediately if a map-integrity alert fires.
- **On events**: startup, config change, reload ok/fail, rollback, and alerts
  (empty whitelist with no ports, BPF map mismatch, drop spikes).

When reporting an outage, capture:

```bash
journalctl -u firewalld --since "48 hours ago" | grep fw-diag
tail -500 /var/log/firewalld-diag.log
curl -s http://127.0.0.1:9090/health | jq .
```

Watch for `reload_fail`, `rollback_fail`, `bpf_tcp_in_empty`, or
`whitelist_cleared`. `bpf_whitelist_partial` with `::1` in the whitelist is
**not** an error — IPv6 is counted separately as `map_wl_v6`.

---

## Emergency recovery

If SSH is blocked by orphaned XDP/TC rules, run from your provider's console
(VNC/serial):

```bash
sudo ./scripts/firewall-emergency-recover.sh [interface]
```

Then whitelist your address before re-enabling:

```bash
firewallctl allow <your-ip>
firewallctl activate
```

**Why `hooks-off` alone can look like a no-op.** XDP is attached with a
`bpf_link` owned by the running `firewalld` process; `ip link set xdp off` does
not drop that link while the daemon is alive. The recovery script works because
it **stops firewalld first** (releasing the link), then detaches — which is why
`firewallctl hooks-off` now stops the service too.

> With `tcp_in = 80,443` only, **SSH (22) is denied** unless your client IP is in
> `firewall.allow`. That is expected policy, not a stuck hook. If 80/443 or an
> allow-listed IP is *also* blocked, that is a bug (false XDP drop / stale
> `bpf_link`) — check `health.map_integrity` and
> `journalctl -u firewalld | grep -E 'bpf_.*_keys_missing'`.

---

## Development

```bash
cd firewall
go test ./...      # or: make test
```

Unit tests cover rule parsing, policy loading and IPv4 BPF key layout. BPF code
generation needs clang with the `bpfel` target; on macOS (build only, no
runtime): `brew install llvm`.

---

## CI, testing and releases

Everything is automated with GitHub Actions. **The workflows run only while the
repository is public** (`if: ${{ !github.event.repository.private }}`), so a
private mirror spends no Actions minutes.

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| **CI** | Push / PR to `dev` or `main` | Installs the BPF toolchain, `make generate && make build` (bpf2go), and runs the full `go test ./...` suite |
| **Release** | Tag `v*.*.*` | Builds Linux `amd64` + `arm64`, stamps the tag into the binary (`-version`), packages tarballs, and publishes a GitHub Release automatically |

Cutting a release is one command — the version is taken from the tag:

```bash
git tag v0.3.0 && git push origin v0.3.0
```

Each release tarball contains `firewalld`, `firewallctl`, example configs and
`docs/API.md`. The in-tree default version is `0.3.0`
(`internal/config/config.go`); a tagged build overrides it with the tag.

---

## License

**Proprietary — private use only.** Commercial use requires the copyright holder's prior written permission; forking or copying the code is not permitted. See [LICENSE](LICENSE).

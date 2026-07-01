# WAF Host Firewall API

REST API for integrating external services (admin panel, automation, monitoring) with the eBPF/XDP host firewall.

## Base URL

Default: `http://127.0.0.1:9090`

Configure via `FIREWALL_LISTEN_ADDR` in `/etc/firewall/firewalld.env`.

## Authentication

All `/api/v1/*` endpoints require a bearer token:

```http
Authorization: Bearer <FIREWALL_API_TOKEN>
```

Set `FIREWALL_API_TOKEN` in `/etc/firewall/firewalld.env`.

## Endpoints

### `GET /health`

Public health check (no auth).

**Response:**
```json
{
  "status": "ok",
  "iface": "eth0",
  "attached": true,
  "configDir": "/etc/firewall"
}
```

### Whitelist (bypass all rules)

| Method | Path | Body |
|--------|------|------|
| GET | `/api/v1/ips/whitelist` | — |
| POST | `/api/v1/ips/whitelist` | `{"ip":"1.2.3.4"}` or CIDR |
| DELETE | `/api/v1/ips/whitelist/{ip}` | — |

Whitelist entries are persisted to `firewall.allow`.

### Blocklist (always drop)

| Method | Path | Body |
|--------|------|------|
| GET | `/api/v1/ips/blocklist` | — |
| POST | `/api/v1/ips/blocklist` | `{"ip":"198.51.100.99"}` |
| DELETE | `/api/v1/ips/blocklist/{ip}` | — |

Blocklist entries are persisted to `firewall.deny`.

### Port allow lists

| Method | Path | Body |
|--------|------|------|
| GET | `/api/v1/ports` | — |
| PUT | `/api/v1/ports` | see below |

**PUT body:**
```json
{
  "tcp_in": [22, 80, 443],
  "udp_in": [53],
  "tcp_out": [80, 443, 3306],
  "udp_out": [53, 123],
  "allow_localhost": true
}
```

Persisted to `ports.conf`. Strict default: traffic not matching these lists is dropped.

### Complex rules

| Method | Path | Body |
|--------|------|------|
| GET | `/api/v1/rules` | — |
| POST | `/api/v1/rules` | `{"rule":"tcp\|in\|d=80\|s=203.0.113.5","action":"pass"}` |
| DELETE | `/api/v1/rules/{id}?file=deny` | — |

**CSF rule format:**
```
tcp/udp/icmp|in/out|s/d=port|s/d=ip|u=uid|g=gid
```

Examples:
- `tcp|in|d=80|s=203.0.113.5`
- `udp|out|d=53|s=10.0.0.0/24`
- `tcp|out|d=22,80,443|s=198.51.100.0/24`
- `tcp|out|d=3306|u=33`

Port ranges: `80-443` or CSF-style `2000_3000`. Multiport (max 15 per complex rule): `22,80,443`.

**Kernel limit:** up to **64** complex rules total (combined from `firewall.allow` and `firewall.deny`). Whitelist/blocklist IPs are not counted toward this limit.

**UID/GID rules** apply only to **outgoing** connections (enforced in TC egress).

### Operations

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/reload` | Re-read config files and refresh BPF maps |
| GET | `/api/v1/stats` | Packet pass/drop counters |

**Stats response:**
```json
{
  "xdp": {"pass": 12345, "drop": 67},
  "tc": {"pass": 8901, "drop": 12}
}
```

## Config files

| File | Purpose |
|------|---------|
| `/etc/firewall/firewall.allow` | Whitelist IPs + allow complex rules |
| `/etc/firewall/firewall.deny` | Blocklist IPs + deny complex rules |
| `/etc/firewall/ports.conf` | Inbound/outbound port allow lists |
| `/etc/firewall/firewalld.env` | Daemon environment (`FIREWALL_API_TOKEN`, `FIREWALL_IFACE`) |

Files are watched via `fsnotify`; changes reload automatically after 500ms debounce.

## Integration example

```bash
TOKEN="your-api-token"
BASE="http://127.0.0.1:9090"

# Block an IP
curl -s -X POST "$BASE/api/v1/ips/blocklist" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.99"}'

# Open HTTPS inbound
curl -s -X PUT "$BASE/api/v1/ports" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tcp_in":[22,80,443],"udp_in":[53],"tcp_out":[80,443],"udp_out":[53]}'
```

## Policy evaluation order

**Ingress (XDP):**
1. Loopback (if enabled)
2. Whitelist → PASS
3. Blocklist → DROP
4. Complex `in` rules
5. `tcp_in` / `udp_in` port match
6. ICMP → PASS
7. Default → DROP

**Egress (TC):**
1. Loopback (if enabled)
2. Whitelist → PASS
3. Blocklist → DROP
4. Complex `out` rules (incl. UID/GID)
5. `tcp_out` / `udp_out` port match
6. ICMP → PASS
7. Default → DROP

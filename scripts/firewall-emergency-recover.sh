#!/usr/bin/env bash
# Run from Hetzner Cloud Console (VNC) if SSH is blocked by orphaned XDP/TC rules.
set -euo pipefail

echo "==> WAF firewall emergency recovery"
echo "    Removes XDP/TC hooks and stops firewalld."

IFACE="${1:-}"
if [[ -z "${IFACE}" ]]; then
  IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
fi
if [[ -z "${IFACE}" ]]; then
  echo "Usage: $0 [interface]" >&2
  echo "Could not detect default interface." >&2
  exit 1
fi

echo "    Interface: ${IFACE}"

systemctl stop firewalld 2>/dev/null || true

if command -v firewallctl >/dev/null 2>&1; then
  echo "==> Detaching hooks via firewallctl"
  FIREWALL_IFACE="${IFACE}" firewallctl hooks-off || true
else
  if ip link show "${IFACE}" 2>/dev/null | grep -q "xdp"; then
    echo "==> Removing XDP from ${IFACE}"
    ip link set dev "${IFACE}" xdp off || true
  fi
  if command -v tc >/dev/null 2>&1; then
    echo "==> Removing TC egress filters on ${IFACE}"
    tc filter del dev "${IFACE}" egress 2>/dev/null || true
    tc qdisc del dev "${IFACE}" clsact 2>/dev/null || true
  fi
fi

rm -f /sys/fs/bpf/fwtest* 2>/dev/null || true

echo "==> Done. Try SSH again."
echo "    Before re-enabling: firewallctl allow <your-ip>"
echo "    Then: firewallctl activate"

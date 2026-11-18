#!/usr/bin/env bash
# Non-interactive installer bundled inside pre-built release tarballs
# (waf-firewall-<version>-<distro>-<arch>.tar.gz). Unlike
# scripts/setup-firewall.sh (which builds firewalld from source and asks
# questions), this script only unpacks pre-built binaries + a pre-built BPF
# object — no compiler toolchain is required on the target host — and runs
# fully automatically so it can be driven by `tar xzf ... && cd ... && sudo
# ./install.sh` with no prompts.
#
# Safe to re-run: existing configs are never overwritten, only seeded from
# examples if missing (same rule as `make install`).
#
# Env overrides (all optional):
#   FIREWALL_IFACE       force the attach interface (default: autodetected
#                         default-route NIC)
#   FIREWALL_CONFIG_DIR  default /etc/firewall
#   FIREWALL_SKIP_START  set to "1" to install + enable but not start now
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${FIREWALL_CONFIG_DIR:-/etc/firewall}"
ENV_FILE="${CONFIG_DIR}/firewalld.env"
BIN_DIR="/usr/local/bin"
UNIT_DIR="/lib/systemd/system"

log() { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }
die() { echo "error: $*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "run as root: sudo $0"
[[ "$(uname -s)" == "Linux" ]] || die "this firewall runs on Linux only"

kernel_major=$(uname -r | cut -d. -f1)
kernel_minor=$(uname -r | cut -d. -f2)
if (( kernel_major < 5 || (kernel_major == 5 && kernel_minor < 17) )); then
  die "kernel >= 5.17 required (found $(uname -r))"
fi

[[ -x "${SCRIPT_DIR}/firewalld" && -x "${SCRIPT_DIR}/firewallctl" ]] \
  || die "firewalld/firewallctl not found next to this script — run from the unpacked release directory"

echo "== WAF eBPF/XDP Host Firewall — release install =="
echo "   Source: ${SCRIPT_DIR}"

# --- runtime dependencies (iproute2 for `ip`/`tc`; the binaries themselves
# are CGO_ENABLED=0 static Go + a pre-built BPF object, so no compiler,
# libbpf, or kernel-headers package is needed on the target host at all). ---
log "Checking runtime dependencies"
if ! command -v ip >/dev/null 2>&1 || ! command -v tc >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq iproute2 ca-certificates curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute ca-certificates curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute ca-certificates curl
  else
    die "no 'ip'/'tc' found and no supported package manager (apt-get/dnf/yum) to install iproute2 — install it manually and re-run"
  fi
fi
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"

log "Installing binaries"
install -m 0755 "${SCRIPT_DIR}/firewalld" "${BIN_DIR}/firewalld"
install -m 0755 "${SCRIPT_DIR}/firewallctl" "${BIN_DIR}/firewallctl"
ln -sf firewallctl "${BIN_DIR}/firewalldctl"

log "Installing config and systemd unit"
install -d "${CONFIG_DIR}" "${UNIT_DIR}"
install -m 0644 "${SCRIPT_DIR}/configs/firewall.allow.example" "${CONFIG_DIR}/firewall.allow.example"
install -m 0644 "${SCRIPT_DIR}/configs/firewall.deny.example" "${CONFIG_DIR}/firewall.deny.example"
install -m 0644 "${SCRIPT_DIR}/configs/ports.conf.example" "${CONFIG_DIR}/ports.conf.example"
install -m 0644 "${SCRIPT_DIR}/configs/firewalld.service" "${UNIT_DIR}/firewalld.service"
[[ -f "${CONFIG_DIR}/firewall.allow" ]] || cp "${CONFIG_DIR}/firewall.allow.example" "${CONFIG_DIR}/firewall.allow"
[[ -f "${CONFIG_DIR}/firewall.deny" ]]  || cp "${CONFIG_DIR}/firewall.deny.example" "${CONFIG_DIR}/firewall.deny"
[[ -f "${CONFIG_DIR}/ports.conf" ]]     || cp "${CONFIG_DIR}/ports.conf.example" "${CONFIG_DIR}/ports.conf"

if [[ ! -f "${ENV_FILE}" ]]; then
  API_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p | tr -d '\n')"
  cat >"${ENV_FILE}" <<EOF
FIREWALL_API_TOKEN=${API_TOKEN}
FIREWALL_CONFIG_DIR=${CONFIG_DIR}
FIREWALL_LISTEN_ADDR=127.0.0.1:9090
EOF
  chmod 0600 "${ENV_FILE}"
  log "Created ${ENV_FILE}"
else
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  API_TOKEN="${FIREWALL_API_TOKEN:-<see ${ENV_FILE}>}"
fi

DETECTED_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
IFACE="${FIREWALL_IFACE:-${DETECTED_IFACE:-eth0}}"
if ! grep -q '^FIREWALL_IFACE=' "${ENV_FILE}" 2>/dev/null; then
  echo "FIREWALL_IFACE=${IFACE}" >>"${ENV_FILE}"
else
  sed -i "s/^FIREWALL_IFACE=.*/FIREWALL_IFACE=${IFACE}/" "${ENV_FILE}"
fi
log "Attach interface: ${IFACE}"

# --- never lock the operator out: whitelist the current SSH client (when
# run over an actual SSH session) and make sure sshd's own port stays
# reachable through tcp_in — this is the non-interactive install, so unlike
# setup-firewall.sh there is no prompt; default to the safe choice both ways. ---
SSH_PORT="${SSH_PORT:-22}"
CALLER_IP="${SSH_CLIENT:-}"
CALLER_IP="${CALLER_IP%% *}"
if [[ -z "${CALLER_IP}" ]]; then
  CALLER_IP="${SSH_CONNECTION:-}"
  CALLER_IP="${CALLER_IP%% *}"
fi
if [[ -n "${CALLER_IP}" ]] && ! grep -qxF "${CALLER_IP}" "${CONFIG_DIR}/firewall.allow" 2>/dev/null; then
  echo "${CALLER_IP}" >>"${CONFIG_DIR}/firewall.allow"
  log "Whitelisted SSH client IP: ${CALLER_IP}"
fi
if ! grep -qE "(^|,)${SSH_PORT}(,|$)" "${CONFIG_DIR}/ports.conf" 2>/dev/null; then
  if grep -q '^tcp_in' "${CONFIG_DIR}/ports.conf" 2>/dev/null; then
    sed -i "s/^tcp_in = .*/tcp_in = ${SSH_PORT},80,443/" "${CONFIG_DIR}/ports.conf"
  else
    printf 'tcp_in = %s,80,443\n' "${SSH_PORT}" >>"${CONFIG_DIR}/ports.conf"
  fi
  log "Added tcp_in=${SSH_PORT} so this session cannot be locked out"
fi

log "Enabling firewalld service"
systemctl daemon-reload
systemctl enable firewalld >/dev/null 2>&1 || true

if [[ "${FIREWALL_SKIP_START:-0}" == "1" ]]; then
  log "FIREWALL_SKIP_START=1 — installed and enabled, not starting now"
else
  log "Starting firewalld"
  systemctl restart firewalld
  ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 2 "http://127.0.0.1:9090/health" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  if [[ "${ok}" -eq 1 ]]; then
    log "Health check OK"
  else
    warn "health check did not respond in 10s — check: journalctl -u firewalld -n 50"
  fi
fi

echo ""
echo "== Firewall installed =="
echo "   Interface:  ${IFACE}"
echo "   Config:     ${CONFIG_DIR}"
echo "   API:        http://127.0.0.1:9090"
echo "   API token:  ${API_TOKEN}"
echo ""
echo "   curl -H \"Authorization: Bearer \${FIREWALL_API_TOKEN}\" http://127.0.0.1:9090/api/v1/ports"
echo "   See docs/API.md for the full API, and NoCONNECT.md if you get locked out."

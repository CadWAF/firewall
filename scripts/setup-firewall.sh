#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="/etc/firewall"
ENV_FILE="${CONFIG_DIR}/firewalld.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This firewall runs on Linux only." >&2
  exit 1
fi

kernel_major=$(uname -r | cut -d. -f1)
kernel_minor=$(uname -r | cut -d. -f2)
if (( kernel_major < 5 || (kernel_major == 5 && kernel_minor < 10) )); then
  echo "Kernel >= 5.10 required (found $(uname -r))." >&2
  exit 1
fi

echo "==> WAF eBPF/XDP Host Firewall setup"
echo "    Source: ${FW_DIR}"

echo "==> Installing build dependencies"
# shellcheck source=ensure-build-deps.sh
source "${SCRIPT_DIR}/ensure-build-deps.sh"
ensure_firewall_build_deps
export PATH="/usr/local/go/bin:${PATH}"

echo "==> Building firewalld"
cd "${FW_DIR}"
make generate
make build

echo "==> Installing binary and configs"
make install

mkdir -p "${CONFIG_DIR}"

if [[ ! -f "${ENV_FILE}" ]]; then
  API_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)"
  cat >"${ENV_FILE}" <<EOF
FIREWALL_API_TOKEN=${API_TOKEN}
FIREWALL_CONFIG_DIR=${CONFIG_DIR}
FIREWALL_LISTEN_ADDR=127.0.0.1:9090
EOF
  chmod 0600 "${ENV_FILE}"
  echo "    Created ${ENV_FILE}"
else
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  API_TOKEN="${FIREWALL_API_TOKEN:-}"
fi

DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
read -r -p "Network interface [${DEFAULT_IFACE:-eth0}]: " IFACE_INPUT || true
IFACE="${IFACE_INPUT:-${DEFAULT_IFACE:-eth0}}"

if ! grep -q '^FIREWALL_IFACE=' "${ENV_FILE}" 2>/dev/null; then
  echo "FIREWALL_IFACE=${IFACE}" >>"${ENV_FILE}"
else
  sed -i "s/^FIREWALL_IFACE=.*/FIREWALL_IFACE=${IFACE}/" "${ENV_FILE}"
fi

SSH_PORT="${SSH_PORT:-22}"
CALLER_IP="${SSH_CLIENT:-}"
CALLER_IP="${CALLER_IP%% *}"
if [[ -n "${CALLER_IP}" ]]; then
  if ! grep -qxF "${CALLER_IP}" "${CONFIG_DIR}/firewall.allow" 2>/dev/null; then
    echo "${CALLER_IP}" >>"${CONFIG_DIR}/firewall.allow"
    echo "    Whitelisted SSH client IP: ${CALLER_IP}"
  fi
fi

if ! grep -qE "(^|,)${SSH_PORT}(,|$)" "${CONFIG_DIR}/ports.conf" 2>/dev/null; then
  echo "WARNING: TCP port ${SSH_PORT} may not be in tcp_in — you could lock yourself out." >&2
  read -r -p "Add ${SSH_PORT} to tcp_in? [Y/n]: " ADD_SSH || true
  if [[ "${ADD_SSH:-Y}" != [nN]* ]]; then
    if grep -q '^tcp_in' "${CONFIG_DIR}/ports.conf"; then
      sed -i "s/^tcp_in = .*/tcp_in = ${SSH_PORT},80,443,8080,3307/" "${CONFIG_DIR}/ports.conf"
    fi
  fi
fi

echo "==> Enabling firewalld service"
systemctl daemon-reload
systemctl enable firewalld

read -r -p "Start firewalld now? Keep this SSH session open and test from another terminal. [y/N]: " START_FW || true
if [[ "${START_FW:-N}" == [yY]* ]]; then
  systemctl restart firewalld
  sleep 1
  if curl -sf "http://127.0.0.1:9090/health" >/dev/null; then
    echo "==> Health check OK"
  else
    echo "WARNING: health check failed — check: journalctl -u firewalld -n 50" >&2
  fi
else
  echo "    Skipped start. When ready: systemctl start firewalld"
  echo "    Or set FIREWALL_EGRESS=false in ${ENV_FILE} to disable outbound filtering."
fi

echo ""
echo "==> Firewall installed"
echo "    Interface:  ${IFACE}"
echo "    Config:     ${CONFIG_DIR}"
echo "    API:        http://127.0.0.1:9090"
echo "    API token:  ${API_TOKEN:-see ${ENV_FILE}}"
echo ""
echo "Example:"
echo "  curl -H \"Authorization: Bearer \${FIREWALL_API_TOKEN}\" http://127.0.0.1:9090/api/v1/ports"
echo ""
echo "See docs/API.md for integration documentation."

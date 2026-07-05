#!/usr/bin/env bash
# Production deploy: pull from GitHub, rebuild firewalld, restart systemd unit.
#
# Run on the Linux host (requires root), e.g.:
#   cd /root/firewall && sudo ./deploy.sh
#
# Environment:
#   DEPLOY_BRANCH=main
#   FIREWALL_SERVICE=firewalld
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
FIREWALL_SERVICE="${FIREWALL_SERVICE:-firewalld}"

for lib in \
  "${SCRIPT_DIR}/scripts/lib/deploy-common.sh" \
  "${SCRIPT_DIR}/../scripts/lib/deploy-common.sh"; do
  if [[ -f "$lib" ]]; then
    # shellcheck source=scripts/lib/deploy-common.sh
    source "$lib"
    break
  fi
done

[[ "$(declare -F deploy_git_pull 2>/dev/null)" == "deploy_git_pull" ]] \
  || { echo "deploy-common.sh not found" >&2; exit 1; }

deploy_parse_args "$@"

if [[ "${EUID}" -ne 0 ]]; then
  deploy_die "Run as root: sudo $0"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  deploy_die "firewall deploy runs on Linux only"
fi

deploy_log "==> WAF Host Firewall production deploy"
deploy_log "    Directory: ${PROJECT_DIR}"

deploy_git_pull "${PROJECT_DIR}"

cd "${PROJECT_DIR}"

if [[ "${DEPLOY_NO_BUILD:-0}" != "1" ]]; then
  deploy_log "==> Building firewalld"
  deploy_run "make generate"
  deploy_run "make build"
  deploy_log "==> Installing binaries and unit file"
  deploy_run "make install"
else
  deploy_log "==> Skipping build (--no-build)"
fi

if systemctl list-unit-files "${FIREWALL_SERVICE}.service" >/dev/null 2>&1; then
  deploy_log "==> Reloading systemd and restarting ${FIREWALL_SERVICE}"
  deploy_run "systemctl daemon-reload"
  deploy_run "systemctl enable '${FIREWALL_SERVICE}'"
  deploy_run "systemctl restart '${FIREWALL_SERVICE}'"

  sleep 2
  if systemctl is-active --quiet "${FIREWALL_SERVICE}"; then
    deploy_log "${FIREWALL_SERVICE} is active"
  else
    deploy_die "${FIREWALL_SERVICE} failed to start — check: journalctl -u ${FIREWALL_SERVICE} -n 50"
  fi
else
  deploy_log "systemd unit ${FIREWALL_SERVICE}.service not found — run scripts/setup-firewall.sh first"
fi

ENV_FILE="/etc/firewall/firewalld.env"
LISTEN="127.0.0.1:9090"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}" 2>/dev/null || true
  LISTEN="${FIREWALL_LISTEN_ADDR:-127.0.0.1:9090}"
fi

deploy_wait_http "http://${LISTEN}/health" "firewalld" 15 || \
  deploy_log "Warning: firewalld HTTP health check failed"

deploy_log "==> Deploy complete"

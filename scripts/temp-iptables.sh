#!/usr/bin/env bash
# Temporary iptables host firewall (iptables-nft / "iptables 1.8+").
#
# - Blocks inbound from WAN except OPEN_TCP / OPEN_UDP
# - ALLOW_ALL: those IPs may reach any port
# - ALLOW_PORTS: IP:ports — only listed ports for that IP
# - Optional DOCKER-USER filter for published container ports
#
# Usage:
#   ./temp-iptables.sh [-c conf] apply|status|flush|dry-run
#
# Safety: on apply, current SSH client IP is auto-added to ALLOW_ALL.
#         SAFETY_SECONDS>0 arms a background rollback if the session dies.

set -euo pipefail

CHAIN_IN="TEMP_FW_IN"
CHAIN_DOCKER="TEMP_FW_DOCKER"
CONF_DEFAULT="/etc/firewall/temp-iptables.conf"
CONF=""
DRY=0
CMD=""

WAN_IF=""
OPEN_TCP="80,443"
OPEN_UDP=""
ALLOW_ALL=""
ALLOW_PORTS=""
DOCKER_FILTER=1
SAFETY_SECONDS=30

usage() {
  cat <<'EOF'
Usage: temp-iptables.sh [-c conf] apply|status|flush|dry-run

  apply     Install rules (auto-whitelists current SSH IP)
  dry-run   Print actions without changing the system
  status    Show TEMP_FW_* chains and jumps
  flush     Remove TEMP_FW_* rules and jumps

Config (see configs/temp-iptables.conf.example):
  OPEN_TCP / OPEN_UDP   world-open ports
  ALLOW_ALL             IPs with access to all ports
  ALLOW_PORTS           "IP:22,8080 IP2:22"
  WAN_IF                empty = auto
  DOCKER_FILTER         1 = also filter DOCKER-USER on WAN
  SAFETY_SECONDS        auto-flush if apply session ends early (0=off)
EOF
}

die() { echo "error: $*" >&2; exit 1; }

need_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root"
}

have() { command -v "$1" >/dev/null 2>&1; }

ipt() {
  if [[ $DRY -eq 1 ]]; then
    echo "+ iptables $*"
    return 0
  fi
  iptables "$@"
}

detect_wan() {
  if [[ -n "$WAN_IF" ]]; then
    echo "$WAN_IF"
    return
  fi
  local via
  via=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  [[ -n "$via" ]] || die "cannot detect WAN interface; set WAN_IF="
  echo "$via"
}

ssh_client_ip() {
  local ip=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    ip=$(awk '{print $1}' <<<"$SSH_CONNECTION")
  elif [[ -n "${SSH_CLIENT:-}" ]]; then
    ip=$(awk '{print $1}' <<<"$SSH_CLIENT")
  fi
  # ignore link-local / empty
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ip"
  fi
}

load_conf() {
  local f="$1"
  [[ -f "$f" ]] || die "config not found: $f"
  # shellcheck disable=SC1090
  source "$f"
}

csv_split() {
  # stdin: a,b,c → lines
  tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -E .
}

ensure_chain() {
  local chain="$1"
  if [[ $DRY -eq 1 ]]; then
    echo "+ iptables -N $chain (or -F if exists)"
    return
  fi
  if iptables -nL "$chain" >/dev/null 2>&1; then
    iptables -F "$chain"
  else
    iptables -N "$chain"
  fi
}

remove_jumps() {
  local parent="$1" target="$2"
  if [[ $DRY -eq 1 ]]; then
    echo "+ remove jumps $parent -> $target"
    return
  fi
  while iptables -C "$parent" -j "$target" 2>/dev/null; do
    iptables -D "$parent" -j "$target"
  done
}

delete_chain() {
  local chain="$1"
  if [[ $DRY -eq 1 ]]; then
    echo "+ iptables -F/-X $chain"
    return
  fi
  if iptables -nL "$chain" >/dev/null 2>&1; then
    iptables -F "$chain"
    iptables -X "$chain"
  fi
}

merge_allow_all() {
  local extra="$1"
  local cur="${ALLOW_ALL:-}"
  if [[ -z "$extra" ]]; then
    echo "$cur"
    return
  fi
  if [[ -z "$cur" ]]; then
    echo "$extra"
    return
  fi
  if grep -Fqw "$extra" <<<"${cur//,/ }"; then
    echo "$cur"
  else
    echo "${cur},${extra}"
  fi
}

build_rules() {
  local wan="$1"
  local ip ports entry host plist p

  ensure_chain "$CHAIN_IN"

  # Return = continue rest of INPUT (docker bridges, established elsewhere)
  ipt -A "$CHAIN_IN" -i lo -j RETURN
  ipt -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

  # Full allowlist
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    ipt -A "$CHAIN_IN" -s "$ip" -j RETURN
  done < <(printf '%s' "${ALLOW_ALL:-}" | csv_split)

  # Per-IP ports (host INPUT — covers sshd on host, and non-DNAT listeners)
  # Format: "1.2.3.4:22,8080 5.6.7.8:22"
  for entry in ${ALLOW_PORTS:-}; do
    [[ "$entry" == *:* ]] || continue
    host=${entry%%:*}
    plist=${entry#*:}
    while IFS= read -r p; do
      ipt -A "$CHAIN_IN" -s "$host" -p tcp -m tcp --dport "$p" -j RETURN
    done < <(printf '%s' "$plist" | csv_split)
  done

  # World-open ports on WAN only
  if [[ -n "${OPEN_TCP:-}" ]]; then
    ipt -A "$CHAIN_IN" -i "$wan" -p tcp -m multiport --dports "$OPEN_TCP" -j RETURN
  fi
  if [[ -n "${OPEN_UDP:-}" ]]; then
    ipt -A "$CHAIN_IN" -i "$wan" -p udp -m multiport --dports "$OPEN_UDP" -j RETURN
  fi

  # Drop everything else arriving on WAN; other ifaces pass through
  ipt -A "$CHAIN_IN" -i "$wan" -j DROP
  ipt -A "$CHAIN_IN" -j RETURN

  # Jump from INPUT (insert at top)
  if [[ $DRY -eq 1 ]]; then
    echo "+ iptables -I INPUT 1 -j $CHAIN_IN"
  else
    remove_jumps INPUT "$CHAIN_IN"
    iptables -I INPUT 1 -j "$CHAIN_IN"
  fi

  if [[ "${DOCKER_FILTER:-1}" == "1" ]]; then
    ensure_chain "$CHAIN_DOCKER"
    ipt -A "$CHAIN_DOCKER" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      ipt -A "$CHAIN_DOCKER" -i "$wan" -s "$ip" -j RETURN
    done < <(printf '%s' "${ALLOW_ALL:-}" | csv_split)

    for entry in ${ALLOW_PORTS:-}; do
      [[ "$entry" == *:* ]] || continue
      host=${entry%%:*}
      plist=${entry#*:}
      while IFS= read -r p; do
        ipt -A "$CHAIN_DOCKER" -i "$wan" -s "$host" -p tcp -m tcp --dport "$p" -j RETURN
      done < <(printf '%s' "$plist" | csv_split)
    done

    if [[ -n "${OPEN_TCP:-}" ]]; then
      ipt -A "$CHAIN_DOCKER" -i "$wan" -p tcp -m multiport --dports "$OPEN_TCP" -j RETURN
    fi
    if [[ -n "${OPEN_UDP:-}" ]]; then
      ipt -A "$CHAIN_DOCKER" -i "$wan" -p udp -m multiport --dports "$OPEN_UDP" -j RETURN
    fi

    ipt -A "$CHAIN_DOCKER" -i "$wan" -j DROP
    ipt -A "$CHAIN_DOCKER" -j RETURN

    if [[ $DRY -eq 1 ]]; then
      echo "+ ensure DOCKER-USER exists; -I DOCKER-USER 1 -j $CHAIN_DOCKER"
    else
      if ! iptables -nL DOCKER-USER >/dev/null 2>&1; then
        iptables -N DOCKER-USER
        # Docker normally inserts jump; if missing, traffic still may bypass — warn
        echo "warn: DOCKER-USER was missing; created empty chain (restart docker if publish filter seems ignored)" >&2
      fi
      remove_jumps DOCKER-USER "$CHAIN_DOCKER"
      iptables -I DOCKER-USER 1 -j "$CHAIN_DOCKER"
    fi
  fi
}

do_flush() {
  remove_jumps INPUT "$CHAIN_IN"
  remove_jumps DOCKER-USER "$CHAIN_DOCKER" 2>/dev/null || true
  delete_chain "$CHAIN_IN"
  delete_chain "$CHAIN_DOCKER"
  echo "flushed $CHAIN_IN / $CHAIN_DOCKER"
}

do_status() {
  echo "=== iptables $($(have iptables) && iptables -V) ==="
  echo "--- INPUT (first 15) ---"
  iptables -nL INPUT --line-numbers | head -20
  echo "--- $CHAIN_IN ---"
  iptables -nL "$CHAIN_IN" --line-numbers 2>/dev/null || echo "(absent)"
  echo "--- DOCKER-USER (first 15) ---"
  iptables -nL DOCKER-USER --line-numbers 2>/dev/null | head -20 || echo "(absent)"
  echo "--- $CHAIN_DOCKER ---"
  iptables -nL "$CHAIN_DOCKER" --line-numbers 2>/dev/null || echo "(absent)"
}

arm_safety() {
  local sec="$1"
  [[ "$sec" =~ ^[0-9]+$ ]] || return 0
  [[ "$sec" -gt 0 ]] || return 0
  [[ $DRY -eq 1 ]] && return 0

  local marker="/run/temp-iptables.ok"
  rm -f "$marker"
  echo "safety: confirm within ${sec}s — touch $marker  OR  re-run: $0 -c ${CONF} confirm"
  echo "        otherwise rules will be flushed automatically."

  (
    sleep "$sec"
    if [[ -f "$marker" ]]; then
      echo "safety: confirmed — keeping rules"
      exit 0
    fi
    echo "safety: no confirm — flushing TEMP_FW_*" >&2
    "$0" -c "$CONF" flush || true
  ) >/dev/null 2>&1 &
  disown || true
}

do_confirm() {
  touch /run/temp-iptables.ok
  echo "confirmed — safety timer will keep rules"
}

# --- argv ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config) CONF="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    apply|status|flush|dry-run|confirm)
      CMD="$1"; shift ;;
    *) die "unknown arg: $1 (see --help)" ;;
  esac
done

[[ -n "$CMD" ]] || { usage; exit 1; }

if [[ "$CMD" == "dry-run" ]]; then
  DRY=1
  CMD=apply
fi

CONF="${CONF:-$CONF_DEFAULT}"
# Allow running from repo without /etc copy
if [[ ! -f "$CONF" ]]; then
  here=$(cd "$(dirname "$0")/.." && pwd)
  if [[ -f "$here/configs/temp-iptables.conf" ]]; then
    CONF="$here/configs/temp-iptables.conf"
  elif [[ -f "$here/configs/temp-iptables.conf.example" && "$CMD" != "flush" && "$CMD" != "status" && "$CMD" != "confirm" ]]; then
    echo "warn: using example config $here/configs/temp-iptables.conf.example" >&2
    CONF="$here/configs/temp-iptables.conf.example"
  fi
fi

case "$CMD" in
  status)
    need_root
    do_status
    ;;
  flush)
    need_root
    do_flush
    ;;
  confirm)
    need_root
    do_confirm
    ;;
  apply)
    need_root
    have iptables || die "iptables not found"
    load_conf "$CONF"
    wan=$(detect_wan)

    me=$(ssh_client_ip || true)
    if [[ -n "$me" ]]; then
      ALLOW_ALL=$(merge_allow_all "$me")
      echo "auto-whitelist SSH client: $me"
    else
      echo "warn: could not detect SSH client IP — ensure ALLOW_ALL has your IP" >&2
    fi

    echo "WAN=$wan OPEN_TCP=${OPEN_TCP:-} OPEN_UDP=${OPEN_UDP:-}"
    echo "ALLOW_ALL=$ALLOW_ALL"
    echo "ALLOW_PORTS=${ALLOW_PORTS:-}"
    echo "DOCKER_FILTER=${DOCKER_FILTER:-1} SAFETY_SECONDS=${SAFETY_SECONDS:-0}"

    # rebuild clean
    if [[ $DRY -eq 0 ]]; then
      remove_jumps INPUT "$CHAIN_IN"
      remove_jumps DOCKER-USER "$CHAIN_DOCKER" 2>/dev/null || true
    fi
    build_rules "$wan"

    if [[ $DRY -eq 0 ]]; then
      echo "applied."
      arm_safety "${SAFETY_SECONDS:-0}"
      do_status
    else
      echo "(dry-run done)"
    fi
    ;;
esac

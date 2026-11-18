#!/usr/bin/env bash
# Ensure clang/llvm/libbpf headers and Go >= 1.23 for firewalld builds.
# Safe to source or execute as root on Linux.

ensure_firewall_build_deps() {
  local go_min_major=1
  local go_min_minor=23
  local go_install_version="${FIREWALL_GO_VERSION:-1.23.8}"

  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ensure-build-deps: must run as root" >&2
    return 1
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
      clang llvm libbpf-dev "linux-headers-$(uname -r)" \
      make curl ca-certificates tar \
      golang-go || apt-get install -y -qq golang || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y clang llvm libbpf-devel "kernel-headers-$(uname -r)" make curl tar golang || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y clang llvm libbpf-devel kernel-headers make curl tar golang || true
  fi

  _firewall_go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local ver major minor
    ver="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    [[ -n "$ver" ]] || return 1
    major="${ver%%.*}"
    minor="${ver#*.}"
    minor="${minor%%.*}"
    [[ "$major" -gt "$go_min_major" ]] && return 0
    [[ "$major" -eq "$go_min_major" && "$minor" -ge "$go_min_minor" ]]
  }

  # Prefer /usr/local/go when present (official toolchain).
  if [[ -x /usr/local/go/bin/go ]]; then
    export PATH="/usr/local/go/bin:${PATH}"
  fi

  if _firewall_go_ok; then
    echo "ensure-build-deps: using $(command -v go) ($(go env GOVERSION))"
    return 0
  fi

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)
      echo "ensure-build-deps: unsupported arch $(uname -m); install Go ${go_min_major}.${go_min_minor}+ manually" >&2
      return 1
      ;;
  esac

  local tarball="go${go_install_version}.linux-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  local tmp
  tmp="$(mktemp -d)"
  echo "ensure-build-deps: installing Go ${go_install_version} from ${url}"
  curl -fsSL "${url}" -o "${tmp}/${tarball}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp}/${tarball}"
  rm -rf "${tmp}"
  export PATH="/usr/local/go/bin:${PATH}"

  if ! _firewall_go_ok; then
    echo "ensure-build-deps: Go ${go_min_major}.${go_min_minor}+ still missing after install" >&2
    return 1
  fi
  echo "ensure-build-deps: using $(command -v go) ($(go env GOVERSION))"
}

# Allow: sudo ./scripts/ensure-build-deps.sh
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
  ensure_firewall_build_deps
fi

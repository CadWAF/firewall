#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/internal/bpf"

CLANG="${CLANG:-clang}"
if command -v /usr/local/opt/llvm/bin/clang >/dev/null 2>&1; then
  CLANG=/usr/local/opt/llvm/bin/clang
elif command -v /opt/homebrew/opt/llvm/bin/clang >/dev/null 2>&1; then
  CLANG=/opt/homebrew/opt/llvm/bin/clang
fi

exec go run github.com/cilium/ebpf/cmd/bpf2go \
  -no-strip \
  -cc "${CLANG}" \
  -cflags "-O2 -g -Wall -Wno-unused-value -target bpfel -mllvm -bpf-stack-size=1024" \
  -target bpfel \
  Firewall \
  ../../bpf/firewall.c \
  -- -I../../bpf -I../../bpf/headers

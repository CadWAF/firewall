#!/usr/bin/env bash
# Build release tarballs for multiple distros/architectures using local
# Docker (not CI). One tarball per (distro, arch): identical, statically
# linked (CGO_ENABLED=0) firewalld/firewallctl + a pre-built, target-
# independent BPF object — the same binary genuinely runs unmodified on any
# of these distros, so each is built and unit-tested inside that distro's
# own container to prove it, not just relabeled.
#
# Usage:
#   ./scripts/build-release.sh [version]
#
# version defaults to the current `git describe`. Output goes to dist/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")}"
VERSION="${VERSION#v}"
DIST_DIR="${ROOT}/dist"
GOARCHES=(amd64 arm64)

# name -> base image. All use apt or dnf, matching ensure-build-deps.sh.
declare -A DISTROS=(
  [ubuntu2204]="ubuntu:22.04"
  [ubuntu2404]="ubuntu:24.04"
  [debian12]="debian:12"
  [almalinux9]="almalinux:9"
)

command -v docker >/dev/null 2>&1 || { echo "error: docker not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: docker daemon not reachable — start Docker Desktop" >&2; exit 1; }

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

echo "== Building waf-firewall ${VERSION} for: ${!DISTROS[*]} x ${GOARCHES[*]} =="

for distro in "${!DISTROS[@]}"; do
  image="${DISTROS[${distro}]}"
  echo ""
  echo "---- ${distro} (${image}) ----"

  if [[ "${image}" == ubuntu:* || "${image}" == debian:* ]]; then
    install_cmd='export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq clang llvm libbpf-dev linux-headers-generic make golang-go git ca-certificates 2>/dev/null \
        || apt-get install -y -qq clang llvm libbpf-dev make golang-go git ca-certificates'
  else
    install_cmd='dnf install -y -q clang llvm libbpf-devel kernel-headers make golang git ca-certificates'
  fi

  # One container builds+tests both GOARCHes for this distro: the C/BPF
  # object is arch-independent bytecode and CGO_ENABLED=0 Go cross-compiles
  # without a matching C toolchain, so no QEMU/buildx is needed.
  docker run --rm \
    -v "${ROOT}:/src:ro" \
    -v "${DIST_DIR}:/dist" \
    -w /build \
    "${image}" \
    bash -euc "
      ${install_cmd}
      cp -a /src /build
      cd /build
      go version
      make generate
      go test ./... -count=1
      for arch in ${GOARCHES[*]}; do
        CGO_ENABLED=0 GOOS=linux GOARCH=\${arch} go build -buildvcs=false -o bin/firewalld ./cmd/firewalld
        CGO_ENABLED=0 GOOS=linux GOARCH=\${arch} go build -buildvcs=false -o bin/firewallctl ./cmd/firewallctl
        file bin/firewalld

        pkg=\"waf-firewall-${VERSION}-${distro}-\${arch}\"
        mkdir -p \"\${pkg}/configs\" \"\${pkg}/docs\" \"\${pkg}/scripts\"
        cp bin/firewalld bin/firewallctl \"\${pkg}/\"
        cp scripts/install-release.sh \"\${pkg}/install.sh\"
        chmod +x \"\${pkg}/install.sh\"
        cp configs/*.example \"\${pkg}/configs/\"
        cp configs/firewalld.service \"\${pkg}/configs/\"
        cp docs/API.md \"\${pkg}/docs/\"
        cp README.md NoCONNECT.md LICENSE \"\${pkg}/\"
        tar czf \"/dist/\${pkg}.tar.gz\" \"\${pkg}\"
        echo \"built /dist/\${pkg}.tar.gz\"
      done
    "
done

echo ""
echo "== Done =="
ls -lh "${DIST_DIR}"
( cd "${DIST_DIR}" && sha256sum ./*.tar.gz > SHA256SUMS.txt && cat SHA256SUMS.txt )

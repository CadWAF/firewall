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
GO_VERSION="1.23.8"

# name=image pairs, not an associative array — this script also needs to
# run under macOS's stock /bin/bash (3.2, no `declare -A`). All distros use
# apt or dnf, matching ensure-build-deps.sh.
DISTROS=(
  "ubuntu2204=ubuntu:22.04"
  "ubuntu2404=ubuntu:24.04"
  "debian12=debian:12"
  "almalinux9=almalinux:9"
)

command -v docker >/dev/null 2>&1 || { echo "error: docker not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: docker daemon not reachable — start Docker Desktop" >&2; exit 1; }

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

echo "== Building waf-firewall ${VERSION} for: ${DISTROS[*]} x ${GOARCHES[*]} =="

for pair in "${DISTROS[@]}"; do
  distro="${pair%%=*}"
  image="${pair#*=}"
  echo ""
  echo "---- ${distro} (${image}) ----"

  # Go always comes from the official tarball (pinned ${GO_VERSION}), never
  # the distro package — several of these ship a Go too old for go.mod
  # (go 1.23.0), e.g. Ubuntu 22.04's golang-go is 1.18.
  go_install="curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-\$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz -o /tmp/go.tgz
    tar -C /usr/local -xzf /tmp/go.tgz
    export PATH=/usr/local/go/bin:\${PATH}"

  # generate-bpf.sh passes -mllvm -bpf-stack-size=1024, an LLVM backend flag
  # this program's compiled rule-eval structs need. Ubuntu 22.04 and
  # Debian 12 both still ship clang-14, which doesn't recognise it —
  # verified against a real build in each container, not assumed — so
  # those two get clang-18 from apt.llvm.org instead of the distro package.
  # Ubuntu 24.04 (clang-18) and AlmaLinux 9 (clang-21) already work stock.
  clang_bin=clang
  if [[ "${image}" == "ubuntu:22.04" || "${image}" == "debian:12" ]]; then
    clang_bin=clang-18
  fi

  if [[ "${image}" == ubuntu:* || "${image}" == debian:* ]]; then
    install_cmd="export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq clang llvm libbpf-dev make git ca-certificates curl file wget lsb-release gnupg software-properties-common
      ${go_install}"
    if [[ "${clang_bin}" == "clang-18" ]]; then
      install_cmd="${install_cmd}
      wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
      chmod +x /tmp/llvm.sh
      /tmp/llvm.sh 18 >/tmp/llvm-install.log 2>&1 || (tail -50 /tmp/llvm-install.log; exit 1)"
    fi
  else
    # libbpf-devel lives in CRB (CodeReady Builder), disabled by default.
    # --allowerasing: the minimal image ships curl-minimal, which conflicts
    # with the full curl package on a plain install.
    install_cmd="dnf install -y -q dnf-plugins-core
      dnf config-manager --set-enabled crb
      dnf install -y -q --allowerasing clang llvm libbpf-devel make git ca-certificates curl tar file
      ${go_install}"
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
      cp -a /src/. /build/
      cd /build
      go version
      ${clang_bin} --version | head -1
      CLANG=${clang_bin} make generate
      go test ./... -count=1
      for arch in ${GOARCHES[*]}; do
        CGO_ENABLED=0 GOOS=linux GOARCH=\${arch} go build -buildvcs=false -o bin/firewalld ./cmd/firewalld
        CGO_ENABLED=0 GOOS=linux GOARCH=\${arch} go build -buildvcs=false -o bin/firewallctl ./cmd/firewallctl
        file bin/firewalld

        pkg=\"waf-firewall-${VERSION}-${distro}-\${arch}\"
        mkdir -p \"\${pkg}/configs\" \"\${pkg}/docs\"
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

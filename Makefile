# Host-level eBPF/XDP firewall (CSF-like)

.PHONY: generate build install clean test

BPF_DIR := bpf
INTERNAL_BPF := internal/bpf
CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Recompile the BPF object from bpf/*.c. Needs clang/llvm. Run this (and commit
# internal/bpf/firewall_bpfel.o) whenever the BPF source changes — it is NOT a
# prerequisite of `build`, so that a host without a compiler can still rebuild
# firewalld from the committed, already-compiled object.
generate:
	go generate ./$(INTERNAL_BPF)/...

# Build the daemons. The BPF object is embedded via //go:embed from the
# committed internal/bpf/firewall_bpfel.o, so this needs only the Go toolchain —
# no clang. To rebuild the object from source first, run `make generate build`.
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) go build -buildvcs=false -o bin/firewalld ./cmd/firewalld
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) go build -buildvcs=false -o bin/firewallctl ./cmd/firewallctl

install: build
	install -d /usr/local/bin /etc/firewall /lib/systemd/system
	install -m 0755 bin/firewalld /usr/local/bin/firewalld
	install -m 0755 bin/firewallctl /usr/local/bin/firewallctl
	ln -sf firewallctl /usr/local/bin/firewalldctl
	install -m 0644 configs/firewall.allow.example /etc/firewall/firewall.allow.example
	install -m 0644 configs/firewall.deny.example /etc/firewall/firewall.deny.example
	install -m 0644 configs/ports.conf.example /etc/firewall/ports.conf.example
	install -m 0644 configs/firewalld.env.example /etc/firewall/firewalld.env.example
	install -m 0644 configs/firewalld.service /lib/systemd/system/firewalld.service
	@if [ ! -f /etc/firewall/firewall.allow ]; then cp configs/firewall.allow.example /etc/firewall/firewall.allow; fi
	@if [ ! -f /etc/firewall/firewall.deny ]; then cp configs/firewall.deny.example /etc/firewall/firewall.deny; fi
	@if [ ! -f /etc/firewall/ports.conf ]; then cp configs/ports.conf.example /etc/firewall/ports.conf; fi

test:
	go test ./...

clean:
	rm -rf bin internal/bpf/*_bpfel*.go internal/bpf/*_bpfeb*.go

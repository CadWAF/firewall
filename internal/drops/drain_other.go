//go:build !linux

package drops

import (
	"context"
	"time"

	fwbpf "github.com/huzenkon/waf-firewall/internal/bpf"
)

// Drainer exists on other platforms only so the engine compiles there; the
// eBPF maps it reads are a Linux object and there is nothing to drain.
type Drainer struct{}

func NewDrainer(*Store, *fwbpf.FirewallObjects, time.Duration, time.Duration) *Drainer {
	return &Drainer{}
}

func (d *Drainer) Run(context.Context) {}

func (d *Drainer) Collect() ([]Entry, error) { return nil, nil }

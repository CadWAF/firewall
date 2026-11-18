package policy

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestVerifyPortMapKeys(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skip(err)
	}
	spec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    2,
		ValueSize:  1,
		MaxEntries: 16,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = m.Close() })

	_ = m.Put(uint16(80), uint8(1))
	_ = m.Put(uint16(443), uint8(1))

	missing, err := VerifyPortMapKeys(m, []uint16{80, 443})
	if err != nil || len(missing) != 0 {
		t.Fatalf("expected no missing, got %v err=%v", missing, err)
	}
	missing, err = VerifyPortMapKeys(m, []uint16{80, 443, 8080})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0] != 8080 {
		t.Fatalf("expected missing 8080, got %v", missing)
	}
}

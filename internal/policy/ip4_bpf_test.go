package policy

import (
	"net"
	"testing"
)

func TestIP4BPFKeyMatchesPacketLayout(t *testing.T) {
	ip := net.ParseIP("146.19.188.230").To4()
	got := ip4BPFKey(ip)
	// iphdr->saddr on little-endian: first wire byte is the low byte of the u32.
	want := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
	if got != want {
		t.Fatalf("ip4BPFKey = %#x, want %#x", got, want)
	}
	if got == 0x9213bce6 {
		t.Fatal("ip4BPFKey still uses big-endian uint32 layout")
	}
}

func TestIP4BPFMask24(t *testing.T) {
	ip := net.ParseIP("10.0.1.5").To4()
	masked := ip4BPFKey(ip) & ip4BPFMask(24)
	// /24 clears the last IPv4 octet (wire byte at offset 3 in iphdr->saddr layout).
	if byte(masked>>24) != 0 {
		t.Fatalf("mask /24 should clear last octet, got %#x", masked)
	}
}

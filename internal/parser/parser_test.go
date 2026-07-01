package parser

import (
	"testing"
)

func TestParseSimpleIPv4(t *testing.T) {
	e, err := ParseLine("1.2.3.4", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != EntrySimpleIP || e.PrefixLen != 32 {
		t.Fatalf("got %+v", e)
	}
}

func TestParseSimpleCIDR(t *testing.T) {
	e, err := ParseLine("10.0.0.0/24", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.PrefixLen != 24 {
		t.Fatalf("prefix = %d", e.PrefixLen)
	}
}

func TestParseComplexRule(t *testing.T) {
	e, err := ParseLine("tcp|in|d=80|s=203.0.113.5", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.Proto != ProtoTCP || e.Direction != DirIn || e.PortSpec != PortDst || e.IPSpec != IPSrc {
		t.Fatalf("got %+v", e)
	}
	if len(e.Ports) != 1 || e.Ports[0] != 80 {
		t.Fatalf("ports = %v", e.Ports)
	}
}

func TestParseMultiport(t *testing.T) {
	e, err := ParseLine("tcp|out|d=22,80,443|s=198.51.100.0/24", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ports) != 3 {
		t.Fatalf("ports = %v", e.Ports)
	}
}

func TestParsePortRange(t *testing.T) {
	e, err := ParseLine("udp|in|d=2000_2005|s=10.0.0.1", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ports) != 6 {
		t.Fatalf("expected 6 ports, got %d", len(e.Ports))
	}
}

func TestParsePortHyphenRange(t *testing.T) {
	e, err := ParseLine("tcp|in|d=80-82|s=203.0.113.5", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ports) != 3 || e.Ports[0] != 80 || e.Ports[2] != 82 {
		t.Fatalf("ports = %v", e.Ports)
	}
}

func TestParseUIDRule(t *testing.T) {
	e, err := ParseLine("tcp|out|d=3306|u=33", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.UIDGIDType != UIDGIDUID || e.UIDGID != 33 {
		t.Fatalf("got %+v", e)
	}
}

func TestParseUIDOnIngressRejected(t *testing.T) {
	_, err := ParseLine("tcp|in|d=80|u=33", ActionPass)
	if err == nil {
		t.Fatal("expected error for uid on ingress")
	}
}

func TestParseICMP(t *testing.T) {
	e, err := ParseLine("icmp|in|d=8|s=1.2.3.4", ActionPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.Proto != ProtoICMP || e.Ports[0] != 8 {
		t.Fatalf("got %+v", e)
	}
}

func TestParseInvalidIP(t *testing.T) {
	_, err := ParseLine("not-an-ip", ActionPass)
	if err == nil {
		t.Fatal("expected error")
	}
}

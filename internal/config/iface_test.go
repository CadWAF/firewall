package config

import "testing"

func TestIsVirtualIface(t *testing.T) {
	virtual := []string{
		"lo", "docker0", "br-010f485bb3cf", "veth1a2b3c4", "vethabcdef",
		"cni0", "flannel.1", "virbr0", "cali123", "kube-ipvs0",
	}
	for _, name := range virtual {
		if !IsVirtualIface(name) {
			t.Fatalf("%q should be virtual", name)
		}
	}
	physical := []string{"eth0", "ens3", "enp1s0", "eno1", "bond0"}
	for _, name := range physical {
		if IsVirtualIface(name) {
			t.Fatalf("%q should not be virtual", name)
		}
	}
}

func TestValidateAttachIface(t *testing.T) {
	if err := ValidateAttachIface("eth0"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAttachIface("br-010f485bb3cf"); err == nil {
		t.Fatal("expected error for docker bridge")
	}
	if err := ValidateAttachIface("veth0"); err == nil {
		t.Fatal("expected error for veth")
	}
}

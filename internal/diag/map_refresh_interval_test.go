package diag

import (
	"testing"
	"time"
)

func TestMapRefreshIntervalDefault(t *testing.T) {
	t.Setenv("FIREWALL_MAP_REFRESH_INTERVAL", "")
	if got := MapRefreshInterval(); got != 12*time.Hour {
		t.Fatalf("default = %v, want 12h", got)
	}
}

func TestMapRefreshIntervalOff(t *testing.T) {
	t.Setenv("FIREWALL_MAP_REFRESH_INTERVAL", "off")
	if got := MapRefreshInterval(); got != 0 {
		t.Fatalf("off = %v, want 0", got)
	}
}

func TestMapRefreshIntervalCustom(t *testing.T) {
	t.Setenv("FIREWALL_MAP_REFRESH_INTERVAL", "6h")
	if got := MapRefreshInterval(); got != 6*time.Hour {
		t.Fatalf("got %v, want 6h", got)
	}
}

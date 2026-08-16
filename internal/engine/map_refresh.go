package engine

import (
	"log"
	"sync/atomic"
	"time"

	"github.com/huzenkon/waf-firewall/internal/diag"
)

// refreshInFlight prevents stampedes when integrity checks and the 12h timer
// both want a refresh.
var refreshInFlight atomic.Bool

// RefreshMaps re-reads policy from disk and ApplyMaps into the live BPF maps.
// XDP/TC hooks stay attached (same bpf_link / tc filter).
func (e *Engine) RefreshMaps(trigger string) {
	if !refreshInFlight.CompareAndSwap(false, true) {
		diag.Log(diag.EventMapRefresh, "trigger="+trigger+" status=skipped_in_flight")
		return
	}
	defer refreshInFlight.Store(false)

	diag.Log(diag.EventMapRefresh, "trigger="+trigger+" status=start")
	if err := e.Reload(); err != nil {
		diag.Log(diag.EventMapRefresh, "trigger="+trigger+" status=fail err="+err.Error())
		log.Printf("map refresh failed (%s): %v", trigger, err)
		return
	}
	diag.Log(diag.EventMapRefresh, "trigger="+trigger+" status=ok hooks=unchanged")
	log.Printf("map refresh ok trigger=%s (XDP/TC hooks unchanged)", trigger)
}

func (e *Engine) periodicMapRefresh() {
	interval := diag.MapRefreshInterval()
	if interval <= 0 {
		diag.Log(diag.EventMapRefresh, "status=disabled")
		return
	}
	diag.Log(diag.EventMapRefresh, "status=scheduled interval="+interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.RefreshMaps("timer")
		}
	}
}

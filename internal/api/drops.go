package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/huzenkon/waf-firewall/internal/drops"
)

// listDrops answers "which addresses were refused, and why".
//
// The counters this replaces could only say how many packets were dropped,
// which tells an operator that something happened and nothing about what. The
// admin panel consumes this to feed its automatic block list; the WAF can use
// it to recognise an address it has not seen at layer 7 yet.
func (h *Handler) listDrops(w http.ResponseWriter, r *http.Request) {
	store := h.Engine.Drops()
	if store == nil {
		// Distinguished from "nothing to report": an empty list would read as
		// a quiet network rather than a switched-off feature.
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{
			"error":   "drop_log_disabled",
			"message": "Refusal recording is off on this node (FIREWALL_DROP_LOG).",
		})

		return
	}

	q := r.URL.Query()
	filter := drops.Filter{
		Reason: q.Get("reason"),
		Limit:  atoiDefault(q.Get("limit"), 500),
	}

	if v := q.Get("min_packets"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			filter.MinCount = n
		}
	}

	// Callers poll; "since" is what keeps them from re-reading the whole table
	// every time.
	if v := q.Get("since"); v != "" {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = ts
		} else if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			filter.Since = time.Unix(secs, 0)
		}
	} else if v := q.Get("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Since = time.Now().Add(-time.Duration(n) * time.Minute)
		}
	}

	entries, err := store.List(r.Context(), filter)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error()})

		return
	}

	writeJSON(w, map[string]any{
		"drops": entries,
		"count": len(entries),
		"as_of": time.Now().UTC().Format(time.RFC3339),
	})
}

func atoiDefault(v string, def int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}

	return n
}

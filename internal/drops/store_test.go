package drops

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()

	s, err := Open(filepath.Join(t.TempDir(), "drops.sqlite"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	return s
}

func TestRecordAccumulatesAcrossDrains(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Each drain carries the delta since the last one, so the counts must add
	// rather than replace — otherwise a busy attacker looks quiet.
	first := []Entry{{IP: "198.51.100.7", Reason: "no_matching_port", Proto: "tcp",
		Packets: 10, FirstSeen: now, LastSeen: now}}
	second := []Entry{{IP: "198.51.100.7", Reason: "no_matching_port", Proto: "tcp",
		Packets: 5, FirstSeen: now.Add(time.Minute), LastSeen: now.Add(time.Minute)}}

	for _, batch := range [][]Entry{first, second} {
		if err := s.Record(ctx, batch); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	got, err := s.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].Packets != 15 {
		t.Fatalf("counts did not accumulate: want 15, got %d", got[0].Packets)
	}
	if !got[0].FirstSeen.Equal(now.UTC()) {
		t.Fatalf("first_seen should stay the earliest: want %v, got %v", now.UTC(), got[0].FirstSeen)
	}
	if !got[0].LastSeen.Equal(now.Add(time.Minute).UTC()) {
		t.Fatalf("last_seen should advance: got %v", got[0].LastSeen)
	}
}

func TestSameAddressDifferentReasonsAreSeparate(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()

	err := s.Record(ctx, []Entry{
		{IP: "198.51.100.8", Reason: "blocklist", Packets: 3, FirstSeen: now, LastSeen: now},
		{IP: "198.51.100.8", Reason: "no_matching_port", Packets: 4, FirstSeen: now, LastSeen: now},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	got, _ := s.List(ctx, Filter{})
	if len(got) != 2 {
		t.Fatalf("an address refused for two reasons is two facts, got %d rows", len(got))
	}
}

func TestListFilters(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	old := now.Add(-48 * time.Hour)

	if err := s.Record(ctx, []Entry{
		{IP: "198.51.100.9", Reason: "rule", Packets: 100, FirstSeen: now, LastSeen: now},
		{IP: "198.51.100.10", Reason: "blocklist", Packets: 2, FirstSeen: now, LastSeen: now},
		{IP: "198.51.100.11", Reason: "rule", Packets: 50, FirstSeen: old, LastSeen: old},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	byReason, _ := s.List(ctx, Filter{Reason: "rule"})
	if len(byReason) != 2 {
		t.Fatalf("reason filter: want 2, got %d", len(byReason))
	}
	if byReason[0].Packets != 100 {
		t.Fatalf("heaviest should come first, got %d", byReason[0].Packets)
	}

	recent, _ := s.List(ctx, Filter{Since: now.Add(-time.Hour)})
	if len(recent) != 2 {
		t.Fatalf("since filter: want 2, got %d", len(recent))
	}

	noisy, _ := s.List(ctx, Filter{MinCount: 10})
	if len(noisy) != 2 {
		t.Fatalf("min count filter: want 2, got %d", len(noisy))
	}
}

func TestPruneRemovesOnlyStaleRows(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	now := time.Now()

	if err := s.Record(ctx, []Entry{
		{IP: "198.51.100.12", Reason: "rule", Packets: 1, FirstSeen: now, LastSeen: now},
		{IP: "198.51.100.13", Reason: "rule", Packets: 1,
			FirstSeen: now.Add(-72 * time.Hour), LastSeen: now.Add(-72 * time.Hour)},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	n, err := s.Prune(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 pruned, got %d", n)
	}

	left, _ := s.List(ctx, Filter{})
	if len(left) != 1 || left[0].IP != "198.51.100.12" {
		t.Fatalf("prune removed the wrong row: %+v", left)
	}
}

func TestEmptyBatchIsNotAnError(t *testing.T) {
	if err := openTemp(t).Record(context.Background(), nil); err != nil {
		t.Fatalf("empty batch should be a no-op, got %v", err)
	}
}

// Package drops persists what the firewall refused, so the question "which
// addresses, and why" has an answer after the fact.
//
// The kernel counts refusals per source in a BPF map; this drains that map on
// a timer and keeps the result in a local SQLite file. SQLite rather than the
// map alone because a map is a fixed-size window that evicts under pressure —
// exactly when the record matters most — and because anything wanting to read
// it (the panel, the WAF) needs something more durable than a kernel object
// that disappears when the daemon restarts.
package drops

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Reason mirrors enum fw_drop_reason in bpf/firewall.h.
type Reason uint8

const (
	ReasonNone      Reason = 0
	ReasonBlocklist Reason = 1
	ReasonRule      Reason = 2
	ReasonNoPort    Reason = 3
)

func (r Reason) String() string {
	switch r {
	case ReasonBlocklist:
		return "blocklist"
	case ReasonRule:
		return "rule"
	case ReasonNoPort:
		return "no_matching_port"
	default:
		return "unknown"
	}
}

// Entry is one source address refused for one reason.
type Entry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Proto     string    `json:"proto"`
	Packets   uint64    `json:"packets"`
	LastPort  uint16    `json:"last_dst_port"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Store struct {
	db   *sql.DB
	path string
}

// Open prepares the database, creating it and its directory if needed.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("drops: create directory: %w", err)
	}

	// WAL so a long read from the API cannot block the drain, and a busy
	// timeout so a concurrent writer waits instead of failing outright.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("drops: open %s: %w", path, err)
	}

	// One writer. SQLite allows exactly that, and letting the pool open more
	// only converts the limit into lock contention.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS drops (
  ip             TEXT    NOT NULL,
  reason         TEXT    NOT NULL,
  proto          TEXT    NOT NULL DEFAULT '',
  packets        INTEGER NOT NULL DEFAULT 0,
  last_dst_port  INTEGER NOT NULL DEFAULT 0,
  first_seen     INTEGER NOT NULL,
  last_seen      INTEGER NOT NULL,
  PRIMARY KEY (ip, reason)
);
CREATE INDEX IF NOT EXISTS drops_last_seen ON drops(last_seen);
CREATE INDEX IF NOT EXISTS drops_packets ON drops(packets DESC);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("drops: migrate: %w", err)
	}

	return nil
}

// Record merges a batch drained from the kernel.
//
// Counts add rather than replace: the map is cleared after each drain, so what
// arrives is the delta since the last one. first_seen keeps the earliest value
// ever recorded, which is what makes "since when" meaningful across restarts.
func (s *Store) Record(ctx context.Context, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("drops: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO drops (ip, reason, proto, packets, last_dst_port, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip, reason) DO UPDATE SET
  packets       = packets + excluded.packets,
  proto         = excluded.proto,
  last_dst_port = excluded.last_dst_port,
  first_seen    = MIN(first_seen, excluded.first_seen),
  last_seen     = MAX(last_seen, excluded.last_seen)
`)
	if err != nil {
		return fmt.Errorf("drops: prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.IP, e.Reason, e.Proto, e.Packets,
			e.LastPort, e.FirstSeen.Unix(), e.LastSeen.Unix()); err != nil {
			return fmt.Errorf("drops: insert %s: %w", e.IP, err)
		}
	}

	return tx.Commit()
}

// Query options for List.
type Filter struct {
	Since    time.Time
	Reason   string
	MinCount uint64
	Limit    int
}

// List returns refused sources, heaviest first.
func (s *Store) List(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}

	query := `SELECT ip, reason, proto, packets, last_dst_port, first_seen, last_seen
	          FROM drops WHERE packets >= ?`
	args := []any{f.MinCount}

	if !f.Since.IsZero() {
		query += " AND last_seen >= ?"
		args = append(args, f.Since.Unix())
	}
	if f.Reason != "" {
		query += " AND reason = ?"
		args = append(args, f.Reason)
	}

	query += " ORDER BY packets DESC LIMIT ?"
	args = append(args, f.Limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("drops: query: %w", err)
	}
	defer rows.Close()

	out := make([]Entry, 0, 64)
	for rows.Next() {
		var e Entry
		var first, last int64
		if err := rows.Scan(&e.IP, &e.Reason, &e.Proto, &e.Packets, &e.LastPort, &first, &last); err != nil {
			return nil, fmt.Errorf("drops: scan: %w", err)
		}
		e.FirstSeen = time.Unix(first, 0).UTC()
		e.LastSeen = time.Unix(last, 0).UTC()
		out = append(out, e)
	}

	// Checked explicitly: a truncated read would otherwise look like a short
	// list, and a short list of attackers reads as "the attack stopped".
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("drops: read: %w", err)
	}

	return out, nil
}

// Prune drops records untouched for longer than the retention window, so the
// file does not grow without bound on a node that is scanned continuously.
func (s *Store) Prune(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()

	res, err := s.db.ExecContext(ctx, `DELETE FROM drops WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("drops: prune: %w", err)
	}

	return res.RowsAffected()
}

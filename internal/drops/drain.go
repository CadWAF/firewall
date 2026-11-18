//go:build linux

package drops

import (
	"context"
	"encoding/binary"
	"log"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	fwbpf "github.com/huzenkon/waf-firewall/internal/bpf"
)

// Drainer moves refusals out of the kernel map and into the store.
//
// It reads and deletes, so the map stays a short buffer rather than a
// long-lived table: the LRU would otherwise evict the quietest attackers to
// make room, which is the opposite of what a record is for.
type Drainer struct {
	Store    *Store
	Map      *ebpf.Map
	Interval time.Duration

	// Records older than this are removed from the store on each pass.
	Retention time.Duration

	// bootTime anchors the kernel's monotonic clock to the wall clock.
	// bpf_ktime_get_ns counts from boot and means nothing on its own.
	bootTime time.Time
}

func NewDrainer(store *Store, objs *fwbpf.FirewallObjects, interval, retention time.Duration) *Drainer {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if retention <= 0 {
		retention = 14 * 24 * time.Hour
	}

	return &Drainer{
		Store:     store,
		Map:       objs.DropLog,
		Interval:  interval,
		Retention: retention,
		bootTime:  bootTime(),
	}
}

// Run drains until the context is cancelled.
func (d *Drainer) Run(ctx context.Context) {
	if d.Map == nil || d.Store == nil {
		return
	}

	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()

	prune := time.NewTicker(time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last pass, so a clean shutdown does not discard what the
			// kernel counted since the previous tick.
			d.drainOnce(context.Background())
			return
		case <-ticker.C:
			d.drainOnce(ctx)
		case <-prune.C:
			if n, err := d.Store.Prune(ctx, d.Retention); err != nil {
				log.Printf("drops: prune failed: %v", err)
			} else if n > 0 {
				log.Printf("drops: pruned %d records older than %s", n, d.Retention)
			}
		}
	}
}

func (d *Drainer) drainOnce(ctx context.Context) {
	entries, err := d.Collect()
	if err != nil {
		log.Printf("drops: collect failed: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	if err := d.Store.Record(ctx, entries); err != nil {
		log.Printf("drops: record failed: %v", err)
	}
}

// Collect reads the map and empties it.
func (d *Drainer) Collect() ([]Entry, error) {
	var (
		key     fwbpf.FirewallDropKey
		record  fwbpf.FirewallDropRecord
		entries []Entry
		stale   []fwbpf.FirewallDropKey
	)

	iter := d.Map.Iterate()
	for iter.Next(&key, &record) {
		ip, ok := decodeAddr(key)
		if !ok {
			// Unparseable key: still remove it, or it occupies a slot forever.
			stale = append(stale, key)
			continue
		}

		entries = append(entries, Entry{
			IP:        ip.String(),
			Reason:    Reason(key.Reason).String(),
			Proto:     protoName(key.Proto),
			Packets:   record.Packets,
			LastPort:  record.LastDstPort,
			FirstSeen: d.wallClock(record.FirstNs),
			LastSeen:  d.wallClock(record.LastNs),
		})
		stale = append(stale, key)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	// Deleted after reading. A packet counted between the read and the delete
	// is lost, which is the right trade: the alternative is holding a lock on
	// the fast path to make a counter exact.
	for i := range stale {
		if err := d.Map.Delete(&stale[i]); err != nil && !isMissing(err) {
			log.Printf("drops: delete key failed: %v", err)
		}
	}

	return entries, nil
}

func decodeAddr(key fwbpf.FirewallDropKey) (netip.Addr, bool) {
	if key.IpVersion == 4 {
		// The kernel stored the address exactly as it arrived on the wire and
		// the map reader reinterpreted those four bytes as a native-endian
		// uint32. Writing it back the same way restores the original order on
		// either endianness — big-endian conversion here would reverse it.
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], key.AddrV4)

		return netip.AddrFrom4(b), true
	}
	if key.IpVersion == 6 {
		return netip.AddrFrom16(key.AddrV6), true
	}

	return netip.Addr{}, false
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return ""
	}
}

func (d *Drainer) wallClock(ktimeNs uint64) time.Time {
	if ktimeNs == 0 {
		return time.Now().UTC()
	}

	return d.bootTime.Add(time.Duration(ktimeNs)).UTC()
}

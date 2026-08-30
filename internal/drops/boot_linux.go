//go:build linux

package drops

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTime is the wall-clock moment the machine booted, used to turn the
// kernel's monotonic timestamps into something that can be compared with
// anything else.
func bootTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}

	return time.Now().Add(-time.Duration(ts.Nano()))
}

func isMissing(err error) bool {
	return err == unix.ENOENT
}

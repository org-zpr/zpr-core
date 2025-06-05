package libvisa

import (
	"time"
)

// VTimeNow returns current time stamp as millisconds since the EPOCH.
func VTimeNow() int64 {
	return VToTimestamp(time.Now())
}

// VToTimestamp return the "visa time" representation of the given time value, `t`.
func VToTimestamp(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}

// VToTime converts visa-timestamp into a time.Time
func VToTime(ts int64) time.Time {
	secs := ts / 1000
	nanos := (ts % 1000) * 1000000
	return time.Unix(secs, nanos)
}

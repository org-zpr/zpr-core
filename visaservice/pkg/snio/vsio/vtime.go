package vsio

import (
	"fmt"
	"time"
)

// VTimeNow returns current time stamp as millisconds since the EPOCH.
func VTimeNow() int64 {
	return VToTimestamp(time.Now())
}

// VExpired takes a visa and tells you if it is expired based on current clock time.
func VExpired(v *Visa) bool {
	return v.GetExpires() < VTimeNow()
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

func (a *Agent) ParseAuthExpires() (time.Time, error) {
	return time.Parse(time.RFC3339, a.AuthExpires)
}

func (a *Agent) MustParseAuthExpires() time.Time {
	if exp, err := time.Parse(time.RFC3339, a.AuthExpires); err != nil {
		panic(fmt.Sprintf("failed to parse agent AuthExpires of '%v'", a.AuthExpires))
	} else {
		return exp
	}
}

func (a *Agent) ParseAuthExpiresOr(t time.Time) time.Time {
	if exp, err := time.Parse(time.RFC3339, a.AuthExpires); err != nil {
		return t
	} else {
		return exp
	}
}

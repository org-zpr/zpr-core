package libvisa

import "time"

// DataCap is a policy constraint and it applies to an (actor,service) tuple.
// If it is grouped then it applies to all the services in the group.
type DataCap struct {
	CapBytes  uint64
	CapPeriod time.Duration
	CapGroup  string // Ideally any constraint could be grouped, but we only track it for data-cap
	SvcID     string
	pStart    time.Time // period start time
	consumed  uint64    // consumed bytes since period start
}

func NewDataCap(serviceID, group string, cbytes uint64, periodInSeconds uint64) *DataCap {
	return &DataCap{
		CapBytes:  cbytes,
		CapPeriod: time.Duration(time.Duration(periodInSeconds) * time.Second),
		CapGroup:  group,
		SvcID:     serviceID,
		pStart:    time.Now(),
	}
}

// Update logs the given bytes as having been consumed since the (internal) start of the period.
// May restart the period.
// Returns the number of bytes remaining.
func (c *DataCap) Update(consumed uint64) uint64 {
	if time.Since(c.pStart) < c.CapPeriod {
		c.consumed += consumed
	} else {
		// We've moved beyond the period so consumed and period can start over.
		c.pStart = time.Now()
		c.consumed = consumed // reset consumed count
	}
	if c.consumed >= c.CapBytes {
		return 0
	}
	return c.CapBytes - c.consumed
}

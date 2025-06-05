package libvisa

import (
	"time"

	"zpr.org/vsx/polio"
)

// VConfig holds visa configurationd details which are set by a policy proc or directly from policy data.
type VConfig struct {
	Lifetime      time.Duration // Set if there is a duration constraint
	DockPEP       uint32        // Dock PEP by index
	DockPEPArgs   interface{}   // one of the PEPArgs* structs
	BWLimit       bool          // yes or no
	BitsPerSecond uint64        // If BWLimit is true, this is bits-per-second
	DataCap       bool
	Cap           *DataCap
	// TODO: Not-valid-after time?
}

// AddBandwidthConstraint adds a bandwidth constraint and performs constraint derivation. Multiple
// bandwidth constraints results in a config with the MAX of all the constraints.
func (vc *VConfig) AddBandwidthConstraint(c *polio.Constraint_Bw) {
	bps := c.Bw.GetBitsPerSec()
	if bps > vc.BitsPerSecond {
		vc.BitsPerSecond = bps
	}
	vc.BWLimit = true
}

// AddDurationConstraint adds a duration (lifetime) constraint and performs constraint derivation.
// If multiple duration constraints are added, we keep the longest one.
func (vc *VConfig) AddDurationConstraint(c *polio.Constraint_Dur) {
	s := time.Duration(c.Dur.GetSeconds()) * time.Second
	if s > vc.Lifetime {
		vc.Lifetime = s
	}
}

// AddCapacityConstraint adds a data-cap constraints and performs constraint derivation.
// If multiple data-cap constraints are added then we keep the one that allows for the
// most (ungrouped) data.
func (vc *VConfig) AddCapacityConstraint(sid, group string, c *polio.Constraint_Cap) {
	cap := NewDataCap(sid, group, c.Cap.GetCapBytes(), c.Cap.GetPeriodSeconds())
	if vc.Cap == nil {
		vc.Cap = cap
	} else {
		if vc.Cap.CapGroup != "" && group == "" {
			vc.Cap = cap // Prefer the ungrouped cap
		}
		// Compare as BYTES/SECOND and pick largest.
		existing := (vc.Cap.CapBytes * 1.0) / uint64(vc.Cap.CapPeriod/time.Second)
		newone := (cap.CapBytes * 1.0) / uint64(cap.CapPeriod/time.Second)
		if newone > existing {
			vc.Cap = cap
		}
	}
	vc.DataCap = true
}

package libvisa_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/libvisa"

	"zpr.org/vsx/polio"
)

func TestCombineBandwidth(t *testing.T) {
	vc := &libvisa.VConfig{}
	vc.AddBandwidthConstraint(&polio.Constraint_Bw{
		Bw: &polio.BWConstraint{
			BitsPerSec: 100,
		},
	})
	require.True(t, vc.BWLimit)
	require.Equal(t, uint64(100), vc.BitsPerSecond)

	vc.AddBandwidthConstraint(&polio.Constraint_Bw{
		Bw: &polio.BWConstraint{
			BitsPerSec: 25, // lower, so should be ignored
		},
	})
	require.True(t, vc.BWLimit)
	require.Equal(t, uint64(100), vc.BitsPerSecond)

	vc.AddBandwidthConstraint(&polio.Constraint_Bw{
		Bw: &polio.BWConstraint{
			BitsPerSec: 250,
		},
	})
	require.True(t, vc.BWLimit)
	require.Equal(t, uint64(250), vc.BitsPerSecond)
}

func TestCombineDuration(t *testing.T) {
	vc := &libvisa.VConfig{}
	vc.AddDurationConstraint(&polio.Constraint_Dur{
		Dur: &polio.DurConstraint{
			Seconds: 60,
		},
	})
	require.Equal(t, time.Duration(60), vc.Lifetime/time.Second)

	vc.AddDurationConstraint(&polio.Constraint_Dur{
		Dur: &polio.DurConstraint{
			Seconds: 30,
		},
	})
	require.Equal(t, time.Duration(60), vc.Lifetime/time.Second) // ignore shorter lifetime setting.

	vc.AddDurationConstraint(&polio.Constraint_Dur{
		Dur: &polio.DurConstraint{
			Seconds: 90,
		},
	})
	require.Equal(t, time.Duration(90), vc.Lifetime/time.Second)
}

func TestCombineDataCap(t *testing.T) {
	vc := &libvisa.VConfig{}
	vc.AddCapacityConstraint("svc1", "", &polio.Constraint_Cap{
		Cap: &polio.DataCapConstraint{
			CapBytes:      200,
			PeriodSeconds: 60,
		},
	})
	require.True(t, vc.DataCap)
	require.Equal(t, uint64(200), vc.Cap.CapBytes)
	require.Equal(t, time.Duration(60), vc.Cap.CapPeriod/time.Second)
	require.Equal(t, "", vc.Cap.CapGroup)

	// This one is ignored as it is the same "size".
	vc.AddCapacityConstraint("svc1", "g1", &polio.Constraint_Cap{
		Cap: &polio.DataCapConstraint{
			CapBytes:      200,
			PeriodSeconds: 60,
		},
	})
	require.True(t, vc.DataCap)
	require.Equal(t, uint64(200), vc.Cap.CapBytes)
	require.Equal(t, time.Duration(60), vc.Cap.CapPeriod/time.Second)
	require.Equal(t, "", vc.Cap.CapGroup)

	// Take this one as it is larger, even though grouped.
	vc.AddCapacityConstraint("svc1", "g1", &polio.Constraint_Cap{
		Cap: &polio.DataCapConstraint{
			CapBytes:      800,
			PeriodSeconds: 60,
		},
	})
	require.True(t, vc.DataCap)
	require.Equal(t, uint64(800), vc.Cap.CapBytes)
	require.Equal(t, time.Duration(60), vc.Cap.CapPeriod/time.Second)
	require.Equal(t, "g1", vc.Cap.CapGroup)

	// Should take this one as it is ungrouped, even though same size.
	vc.AddCapacityConstraint("svc1", "", &polio.Constraint_Cap{
		Cap: &polio.DataCapConstraint{
			CapBytes:      800,
			PeriodSeconds: 60,
		},
	})
	require.True(t, vc.DataCap)
	require.Equal(t, uint64(800), vc.Cap.CapBytes)
	require.Equal(t, time.Duration(60), vc.Cap.CapPeriod/time.Second)
	require.Equal(t, "", vc.Cap.CapGroup)

}

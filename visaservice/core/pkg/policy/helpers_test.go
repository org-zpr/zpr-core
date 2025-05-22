package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vsx/polio"
)

func TestGetMaxVisaLifetime(t *testing.T) {
	p := &polio.Policy{
		Config: []*polio.ConfigSetting{
			&polio.ConfigSetting{
				Key: policy.CKMaxVisaLifetimeSeconds.Key(),
				Val: &polio.ConfigSetting_U64V{
					U64V: uint64((24 * time.Hour) / time.Second),
				},
			},
		},
	}
	require.Equal(t, 24*time.Hour, policy.GetMaxVisaLifetime(p))
}

func TestGetMaxVisaLifetimeSet(t *testing.T) {
	c := policy.NewMaxVisaLifetime(12 * time.Hour)
	p := &polio.Policy{
		Config: []*polio.ConfigSetting{c},
	}
	require.Equal(t, 12*time.Hour, policy.GetMaxVisaLifetime(p))
}

package polio_test

import (
	"testing"
	"time"

	"zpr.org/vs/pkg/polio"

	"github.com/stretchr/testify/require"
)

func TestGetMaxVisaLifetime(t *testing.T) {
	p := &polio.Policy{
		Config: []*polio.ConfigSetting{
			&polio.ConfigSetting{
				Key: polio.CKMaxVisaLifetimeSeconds.Key(),
				Val: &polio.ConfigSetting_U64V{
					U64V: uint64((24 * time.Hour) / time.Second),
				},
			},
		},
	}
	require.Equal(t, 24*time.Hour, p.GetMaxVisaLifetime())
}

func TestGetMaxVisaLifetimeSet(t *testing.T) {
	c := polio.NewMaxVisaLifetime(12 * time.Hour)
	p := &polio.Policy{
		Config: []*polio.ConfigSetting{c},
	}
	require.Equal(t, 12*time.Hour, p.GetMaxVisaLifetime())
}

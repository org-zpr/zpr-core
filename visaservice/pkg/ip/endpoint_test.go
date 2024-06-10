package ip_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/ip"
)

func TestEndpointSdrFromString(t *testing.T) {
	eps, err := ip.EndpointStrFromString("ICMP6/128")
	require.Nil(t, err)
	require.Equal(t, "icmp6", eps.Proto())
	require.Equal(t, "icmp6/128", eps.String())
}

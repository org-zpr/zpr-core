package libvisa_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/libvisa"
)

func TestUpdate(t *testing.T) {
	dc := libvisa.NewDataCap("foosvc", "", 1000, 120)
	require.Equal(t, uint64(1000), dc.Update(0))
	require.Equal(t, uint64(500), dc.Update(500))
	require.Equal(t, uint64(500), dc.Update(0))
	require.Equal(t, uint64(0), dc.Update(1000))
	require.Equal(t, uint64(0), dc.Update(0))
}

package vsio_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/snio/vsio"
)

func TestTimeTimestamp(t *testing.T) {
	clock := time.Now().Truncate(time.Millisecond)

	ts := vsio.VToTimestamp(clock)
	require.NotZero(t, ts)

	tt := vsio.VToTime(ts)
	require.Equal(t, clock, tt)
}

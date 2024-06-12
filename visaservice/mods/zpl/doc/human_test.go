package doc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/doc"
)

func TestParseBandwidthType(t *testing.T) {
	for _, td := range []struct {
		s   string
		bps float64
	}{
		{"0bps", 0},
		{"1bps", 1},
		{"1Bps", 8},
		{"1kbps", 1e3},
		{"1.5Mbps", 1.5e6},
		{"1.25MBps", 10e6},
		{"17e-3Gbps", 17e6},
		{"  100MBps @stuff", 800e6},
	} {
		bps, err := doc.ParseBandwidthType(td.s)
		require.NoError(t, err, td.s)
		require.Equal(t, td.bps, bps)
	}
}

func TestParseBandwidthTypeBadSyntax(t *testing.T) {
	for _, s := range []string{"", "bps", "-1bps", "1Qbps", "1kbph"} {
		_, err := doc.ParseBandwidthType(s)
		require.Error(t, err, s)
	}
}

func TestParseCapacityType(t *testing.T) {
	for _, td := range []struct {
		s       string
		bits    float64
		seconds float64
	}{
		{"0b/s", 0, 1},
		{"0kb/1s", 0, 1},
		{"1b/10s", 1, 10},
		{"1kb/10s", 1e3, 10},
		{"1kB/1e6s", 8e3, 1e6},
		{"125MB/m", 1e9, 60},
		{"125MB/10m", 1e9, 10 * 60},
		{"2.5Gb/2.5h", 2.5e9, 2.5 * 60 * 60},
		{"2.5GB/1.5d", 2.5e9 * 8, 1.5 * 60 * 60 * 24},
		{"  2.5GB/1.5d @stuff", 2.5e9 * 8, 1.5 * 60 * 60 * 24},
	} {
		bits, seconds, err := doc.ParseCapacityType(td.s)
		require.NoError(t, err, td.s)
		require.Equal(t, td.bits, bits, td.s)
		require.Equal(t, td.seconds, seconds, td.s)
	}
}

func TestParseCapacityTypeBadSyntax(t *testing.T) {
	for _, s := range []string{"", "b/s", "-1b/1s", "b/10s", "1Qb/1h", "1Mb/1x"} {
		_, _, err := doc.ParseCapacityType(s)
		require.Error(t, err, s)
	}
}

func TestParseDurationType(t *testing.T) {
	for _, td := range []struct {
		s       string
		seconds float64
	}{
		{"0s", 0},
		{"1s", 1},
		{"10m", 10 * 60},
		{"1.5h", 1.5 * 60 * 60},
		{"3d", 3 * 60 * 60 * 24},
		{" 3d @stuff", 3 * 60 * 60 * 24},
	} {
		seconds, err := doc.ParseDurationType(td.s)
		require.NoError(t, err, td.s)
		require.Equal(t, td.seconds, seconds, td.s)
	}
}

func TestParseDurationTypeBadSyntax(t *testing.T) {
	for _, s := range []string{"", "s", "1x", "-1s"} {
		_, err := doc.ParseDurationType(s)
		require.Error(t, err, s)
	}
}

package snauth_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/snauth"
)

func TestEqualAsStr(t *testing.T) {
	fbytes := []byte{
		0xBB, 0xBA, 0xFE, 0x6E,
		0x6D, 0x46, 0xE2, 0x02,
		0x9F, 0xC6, 0x21, 0xA6,
		0x84, 0xBF, 0xF0, 0x20,
		0xD7, 0xB4, 0x8D, 0xA4,
	}

	fps := "BB:BA:FE:6E:6D:46:E2:02:9F:C6:21:A6:84:BF:F0:20:D7:B4:8D:A4"

	fp, err := snauth.NewSHA1FingerprintFromBytes(fbytes)
	require.Nil(t, err)

	require.True(t, fp.EqualAsStr(fps))
	require.True(t, fp.EqualAsStr(strings.ToLower(fps)))
}

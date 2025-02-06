package auth_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vservice/auth"
)

// Ensure we can insert and retrieve a revocation.
func TestSetAndGetRevoke(t *testing.T) {
	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		nil)

	authsvc.ProposeRevokeCN("12345", "foo.zpr")
	keys := authsvc.ListRevocationKeysFor("12345")
	require.Len(t, keys, 1)
	rvk := authsvc.GetRevoke(keys[0])
	require.NotNil(t, rvk)
	require.Equal(t, "foo.zpr", rvk.GetCredId())
	require.Equal(t, auth.RevokeType_RT_CN, rvk.GetRType())
}

func TestIgnoreDupes(t *testing.T) {
	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		nil)

	authsvc.ProposeRevokeCN("12345", "foo.zpr")
	keys := authsvc.ListRevocationKeysFor("12345")
	require.Len(t, keys, 1)
	{
		authsvc.ProposeRevokeCN("12345", "foo.zpr")
		keys := authsvc.ListRevocationKeysFor("12345")
		require.Len(t, keys, 1)
	}
	rvk := authsvc.GetRevoke(keys[0])
	require.NotNil(t, rvk)
	require.Equal(t, "foo.zpr", rvk.GetCredId())
	require.Equal(t, auth.RevokeType_RT_CN, rvk.GetRType())
}

package auth_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vservice/auth"
)

func TestAddRemoveService(t *testing.T) {
	//addr := net.ParseIP("fc00:3001::1234")
	// revoker := &TRevokingSvc{}
	//pkey, err := rsa.GenerateKey(rand.Reader, 1024)
	//require.Nil(t, err)

	// a := auth.NewAuthenticator(logr.NewTestLogger(), snip.IPToZPRID(addr), 10*time.Minute, "node0", pkey)

	dir := auth.NewDirectory(nil, logr.NewTestLogger())

	require.False(t, dir.HasAuthPrefix("pfx1"))
	require.True(t, dir.Empty())
	n := dir.RemoveServiceByPrefix("pfx1")
	require.Zero(t, n)

	svcAddr := netip.MustParseAddr("fc00:3001::5678")
	feats := auth.DSFeatures{
		SupportValidation: true,
		SupportQuery:      true,
		ValidationAPIVer:  1,
		QueryAPIVer:       1,
	}
	err := dir.AddService("svcpfx", "what_is_domain_for_anyway", svcAddr, 5001, &feats, 1)
	require.Nil(t, err)

	require.Equal(t, 1, dir.Size())

	// twice is ok
	{
		err = dir.AddService("svcpfx", "what_is_domain_for_anyway", svcAddr, 5001, &feats, 1)
		require.Nil(t, err)
		require.Equal(t, 1, dir.Size())
	}

	// and this silently over writes
	{
		err = dir.AddService("svcpfx", "what_is_domain_for_anyway", svcAddr, 5005, &feats, 1)
		require.Nil(t, err)
		require.Equal(t, 1, dir.Size())
	}
	{
		err = dir.AddService("otherpfx", "what_is_domain_for_anyway", netip.MustParseAddr("fc00:3001::9abc"), 5001, &feats, 1)
		require.Nil(t, err)
		require.Equal(t, 2, dir.Size())
	}

	require.True(t, dir.HasAuthPrefix("svcpfx"))
	require.True(t, dir.HasAuthPrefix("otherpfx"))
	require.False(t, dir.Empty())
	n = dir.RemoveServiceByPrefix("svcpfx")
	require.Equal(t, 1, n)
	require.Equal(t, 1, dir.Size())
	require.False(t, dir.HasAuthPrefix("svcpfx"))
	require.False(t, dir.Empty())
	n = dir.RemoveServiceByPrefix("otherpfx")
	require.Equal(t, 1, n)
	require.Equal(t, 0, dir.Size())
	require.True(t, dir.Empty())

	err = dir.AddService("svcpfx1", "dom1", svcAddr, 5001, &feats, 1)
	require.Nil(t, err)
	err = dir.AddService("svcpfx2", "dom2", svcAddr, 5001, &feats, 1)
	require.Nil(t, err)

	require.True(t, dir.HasAuthPrefix("svcpfx1"))
	require.True(t, dir.HasAuthPrefix("svcpfx2"))
	require.False(t, dir.Empty())

	n = dir.RemoveServiceByPrefix("svcpfx2")
	require.Equal(t, 1, n)
	require.True(t, dir.HasAuthPrefix("svcpfx1"))
	require.False(t, dir.HasAuthPrefix("svcpfx2"))
	require.False(t, dir.Empty())

	n = dir.RemoveServiceByPrefix("svcpfx1")
	require.Equal(t, 1, n)
	require.False(t, dir.HasAuthPrefix("svcpfx1"))
	require.False(t, dir.HasAuthPrefix("svcpfx2"))
	require.True(t, dir.Empty())
}

func TestRemoveServiceByContactAddr(t *testing.T) {
	//addr := net.ParseIP("fc00:3001::1234")
	// revoker := &TRevokingSvc{}
	//pkey, err := rsa.GenerateKey(rand.Reader, 1024)
	//require.Nil(t, err)

	//a := auth.NewAuthenticator(logr.NewTestLogger(), snip.IPToZPRID(addr), 10*time.Minute, "node0", pkey)
	dir := auth.NewDirectory(nil, logr.NewTestLogger())

	svcAddr := netip.MustParseAddr("fc00:3001::5678")
	feats := auth.DSFeatures{
		SupportValidation: true,
		SupportQuery:      true,
		ValidationAPIVer:  1,
		QueryAPIVer:       1,
	}

	for n := 0; n < 3; n++ {
		err := dir.AddService(fmt.Sprintf("svcpfx%d", n+1), fmt.Sprintf("dom%d", n+1), svcAddr, uint16(5001+n), &feats, 1)
		require.Nil(t, err)
	}

	require.True(t, dir.HasAuthPrefix("svcpfx1"))
	require.True(t, dir.HasAuthPrefix("svcpfx2"))
	require.True(t, dir.HasAuthPrefix("svcpfx3"))

	dir.RemoveServiceOnContactAddr(netip.MustParseAddr("fc00:3001::aaaa")) // non existant
	require.True(t, dir.HasAuthPrefix("svcpfx1"))
	require.True(t, dir.HasAuthPrefix("svcpfx2"))
	require.True(t, dir.HasAuthPrefix("svcpfx3"))

	dir.RemoveServiceOnContactAddr(svcAddr)
	require.False(t, dir.HasAuthPrefix("svcpfx1"))
	require.False(t, dir.HasAuthPrefix("svcpfx2"))
	require.False(t, dir.HasAuthPrefix("svcpfx3"))

	{
		// Try again but add an alternate address too
		for n := 0; n < 3; n++ {
			err := dir.AddService(fmt.Sprintf("svcpfx%d", n+1), fmt.Sprintf("dom%d", n+1), svcAddr, uint16(5001+n), &feats, 1)
			require.Nil(t, err)
		}
		dir.AddService("svcpfx4", "dom4", netip.MustParseAddr("fc00:3001::aaaa"), 5001, &feats, 1)

		require.True(t, dir.HasAuthPrefix("svcpfx1"))
		require.True(t, dir.HasAuthPrefix("svcpfx2"))
		require.True(t, dir.HasAuthPrefix("svcpfx3"))
		require.True(t, dir.HasAuthPrefix("svcpfx4"))

		dir.RemoveServiceOnContactAddr(netip.MustParseAddr("fc00:3001::aaaa"))
		require.True(t, dir.HasAuthPrefix("svcpfx1"))
		require.True(t, dir.HasAuthPrefix("svcpfx2"))
		require.True(t, dir.HasAuthPrefix("svcpfx3"))
		require.False(t, dir.HasAuthPrefix("svcpfx4"))

		dir.RemoveServiceOnContactAddr(svcAddr)
		require.False(t, dir.HasAuthPrefix("svcpfx1"))
		require.False(t, dir.HasAuthPrefix("svcpfx2"))
		require.False(t, dir.HasAuthPrefix("svcpfx3"))
		require.False(t, dir.HasAuthPrefix("svcpfx4"))
	}
}

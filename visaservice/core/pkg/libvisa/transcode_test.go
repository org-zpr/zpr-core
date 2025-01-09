package libvisa_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vsapi"
	"zpr.org/vsx/polio"
	"zpr.org/vsx/snio/vsio"
)

// Test to make sure that the data is copied over from vsio to thrift visa.
func TestVsioVisaToThrift(t *testing.T) {

	srcTAddr := netip.MustParseAddr("fc00:3001::8")
	dstTAddr := netip.MustParseAddr("fc00:3001::9")

	traf := snip.NewTCPConnect(netip.MustParseAddr("fc00:3002::1"), 3000, netip.MustParseAddr("fc00:3002::2"), 80)

	pol := polio.NewMinimalMatchedPolicy(6, 80, true)
	pol.CPol.Constraints = []*polio.Constraint{
		{
			Carg: &polio.Constraint_Bw{
				Bw: &polio.BWConstraint{
					BitsPerSec: 1000000,
				},
			},
		},
		{
			Carg: &polio.Constraint_Cap{
				Cap: &polio.DataCapConstraint{
					CapBytes:      7000,
					PeriodSeconds: 600,
				},
			},
		},
	}

	vsioVisa, err := libvisa.NewVisaBuilder(33, srcTAddr, dstTAddr).
		WithExpiration(time.Now().Add(time.Hour)).
		WithClientAgentIdent("test-client").
		WithSessionKeyAndEncoding([]byte("test-key"), libvisa.SKEv1).
		WithIssuerID(12345).
		WithTrafficAndPolicy(traf, []*polio.MatchedPolicy{pol}).Visa()

	// fake sign.
	vsioVisa.Sig = &vsio.Signature{
		Type:      19,
		Signature: []byte("signature"),
	}

	require.Nil(t, err)
	require.NotNil(t, vsioVisa)

	// Now convert to thrift and check the result
	thriftVisa := libvisa.VsioVisaToThrift(vsioVisa)
	require.NotNil(t, thriftVisa)

	require.Equal(t, int32(12345), thriftVisa.IssuerID)
	require.Equal(t, int64(33), thriftVisa.Configuration)
	require.Equal(t, vsioVisa.Expires, thriftVisa.Expires)

	require.Equal(t, vsioVisa.Source, thriftVisa.Source)
	require.Equal(t, vsioVisa.Dest, thriftVisa.Dest)
	require.Equal(t, vsioVisa.SourceContact, thriftVisa.SourceContact)
	require.Equal(t, vsioVisa.DestContact, thriftVisa.DestContact)

	// This is a TCP visa.
	require.Equal(t, vsapi.PEPIndex_TCP, thriftVisa.DockPep)
	args := thriftVisa.GetTcpudpPepArgs_()
	require.NotNil(t, args)
	require.Equal(t, vsioVisa.SourceContact, args.SourceContactAddr)
	require.Equal(t, vsioVisa.DestContact, args.DestContactAddr)
	require.Equal(t, 0, int(args.SourcePort))
	require.Equal(t, 80, int(args.DestPort))
	require.False(t, args.Server)

	for _, icmp_t := range libvisa.ICMPAllowIfTCPVisa {
		require.Contains(t, args.IcmpAllowed, int32(icmp_t))
	}

	require.Nil(t, thriftVisa.GetIcmpPepArgs_())

	require.Equal(t, int32(vsioVisa.SessionKey.Format), thriftVisa.SessionKey.Format)
	require.Equal(t, vsioVisa.SessionKey.IngressKey, thriftVisa.SessionKey.IngressKey)
	require.Equal(t, vsioVisa.SessionKey.EgressKey, thriftVisa.SessionKey.EgressKey)

	require.NotNil(t, thriftVisa.GetCons())
	cons := thriftVisa.GetCons()
	require.True(t, cons.Bw)
	require.Equal(t, int64(1000000), cons.BwLimitBps)
	require.NotEmpty(t, cons.DataCapID)
	require.Equal(t, int64(7000), cons.DataCapBytes)

	require.NotNil(t, thriftVisa.GetSig())
	require.Equal(t, int32(vsioVisa.Sig.Type), thriftVisa.Sig.Type)
	require.Equal(t, vsioVisa.Sig.Signature, thriftVisa.Sig.Signature)
}

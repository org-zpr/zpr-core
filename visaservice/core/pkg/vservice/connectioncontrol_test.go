package vservice_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/missing/zpl/compiler"
	"zpr.org/vs/pkg/missing/zpl/fs"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snio/vsio"
	"zpr.org/vs/pkg/snio/zds"
	"zpr.org/vs/pkg/vservice"
)

const basicPolicyTwoDS = `
zpl_format: 2
services:
  http:
    tcp: 80
  auth:
    tcp: 5001
zpr:
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [ca0.x509.cn, eq, n0.internal]
      address: "fc00:3001:1::11"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
      services: [http] #add web access to node
      policies:
         - desc: web access
           conditions:
             - desc: foo fee
               attrs:
                 - [ca0.foo, eq, fee]
           constraints:
             duration: 90s

  visaservice:
    provider:
      - [ca0.foo, eq, fox]
    admin_attrs:
      - [ca0.foo, eq, fee]
  topology:
  datasources:
    ca0:
      api: validation/1
      authority:
        encoding: pem
        cert_data: $import[ca0-cert.pem]
    simplev:
        api: validation/1
        endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[sv-cert.pem]

communications:
  systems:
    mathiasland:
      desc: mathiasland
`

const AuthAttrExtRSA = "ext:ca-rsa-v1"
const AuthAttrExtOpenID = "ext:openid"

func makeVSWithPolicy(t *testing.T, pyaml string) (*vservice.VSInst, *policy.Policy) {
	llog := logr.NewTestLogger()

	testDS := new(TestDS)
	testDS.recs = make(map[string]*vsio.Agent)

	// Minimal config:
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)
	vc := vservice.VSIConfig{
		Log:             llog,
		HopCount:        uint(99),
		AgentSigningKey: pk,
		Directory:       testDS,
	}

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(&vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	// Compile and install the policy
	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/sv-cert.pem", []byte(simplevCert))
	opts := &compiler.CompileOpts{
		Revision: "foo1",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)
	pp := policy.NewPolicyFromPol(plcy, llog)
	svc.InstallPolicy(policy.InitialConfiguration, 1, pp)

	return svc, pp
}

func TestSelectDSPrefixInternal(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)
	cresp := &zds.ChallengeResponse{
		ChalSpec: "",
		// RespSpec:    snauth.AuthAttrExtRSA.String(),
		RespSpec:    "cert:x509:?cn=goo.goo",
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		// DockAddr:
		// ReqAddr:
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0", adom)
}

func TestSelectDSPrefixExternal(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)
	cresp := &zds.ChallengeResponse{
		ChalSpec:    "",
		RespSpec:    AuthAttrExtRSA,
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		//DockAddr: netip.Addr{},
		//ReqAddr:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom)

}

func TestSelectDSPrefixInconsistentAuthority(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp := &zds.ChallengeResponse{
		ChalSpec:    "",
		RespSpec:    AuthAttrExtRSA,
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		//DockAddr: netip.Addr{},
		//ReqAddr:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp},
		Claims: map[string]string{
			"authority": "ca0", // Will accept 'authority' or 'zpr.authority'
		},
	}

	// In this case it will fail because actually the RespSpect determines
	// if we are to use EXTERNAL type authority. And ca0 is an internal type.
	_, err := svc.SelectValidateDSPrefix(p, cr)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown auth service")

}

func TestSelectDSPrefixMultipleMixed(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtRSA,
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=goo.goo",
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		// DockAddr: netip.Addr{},
		// ReqAddr:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp1, cresp2},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom) // Incredibly, the internal auth is just ignored!
}

func TestSelectDSPrefixMultipleInternal(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=ga.ga",
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=goo.goo",
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		// DockZPRAddr: netip.Addr{},
		// EpID:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp1, cresp2},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0", adom)
}

func TestSelectDSPrefixMultipleInternalWithAuth(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=ga.ga",
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:ca99?cn=goo.goo",
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		//DockZPRAddr: netip.Addr{},
		//EpID:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp1, cresp2},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0,ca99", adom) // In this case you can have multiple "domains" ?
}

func TestSelectDSPrefixMultipleExternal(t *testing.T) {
	t.Skip("waiting for compiler port")
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtRSA,
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtOpenID,
	}

	cr := &vsio.VSConnectRequest{
		ConId: "con_key_1",
		//DockZPRAddr: netip.Addr{},
		//EpID:        snip.ZPRID{},
		Chal:     nil,
		ChalResp: []*zds.ChallengeResponse{cresp1, cresp2},
		Claims:   nil,
	}

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom)
}

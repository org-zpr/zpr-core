package vservice_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/fs"

	"zpr.org/vsx/snio/zds"

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

	// Minimal config:
	vc := vservice.VSIConfig{
		Log:      llog,
		HopCount: uint(99),
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

func appendChallengeResponse(t *testing.T, cr *vsapi.ConnectRequest, chalResp *zds.ChallengeResponse) {
	pbuf, err := proto.Marshal(chalResp)
	require.Nil(t, err)
	cr.ChallengeResponses = append(cr.ChallengeResponses, pbuf)
}

func TestSelectDSPrefixInternal(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)
	cresp := &zds.ChallengeResponse{
		ChalSpec: "",
		// RespSpec:    snauth.AuthAttrExtRSA.String(),
		RespSpec:    "cert:x509:?cn=goo.goo",
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID:       1,
		ChallengeResponses: nil,
	}
	appendChallengeResponse(t, cr, cresp)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0", adom)
}

func TestSelectDSPrefixExternal(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)
	cresp := &zds.ChallengeResponse{
		ChalSpec:    "",
		RespSpec:    AuthAttrExtRSA,
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims:       nil,
	}
	appendChallengeResponse(t, cr, cresp)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom)

}

func TestSelectDSPrefixInconsistentAuthority(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp := &zds.ChallengeResponse{
		ChalSpec:    "",
		RespSpec:    AuthAttrExtRSA,
		NonceOffset: 0,
		NonceLen:    0,
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims: map[string]string{
			"authority": "ca0", // Will accept 'authority' or 'zpr.authority'
		},
	}
	appendChallengeResponse(t, cr, cresp)

	// In this case it will fail because actually the RespSpect determines
	// if we are to use EXTERNAL type authority. And ca0 is an internal type.
	_, err := svc.SelectValidateDSPrefix(p, cr)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown auth service")

}

func TestSelectDSPrefixMultipleMixed(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtRSA,
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=goo.goo",
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims:       nil,
	}
	appendChallengeResponse(t, cr, cresp1)
	appendChallengeResponse(t, cr, cresp2)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom) // Incredibly, the internal auth is just ignored!
}

func TestSelectDSPrefixMultipleInternal(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=ga.ga",
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=goo.goo",
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims:       nil,
	}
	appendChallengeResponse(t, cr, cresp1)
	appendChallengeResponse(t, cr, cresp2)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0", adom)
}

func TestSelectDSPrefixMultipleInternalWithAuth(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:?cn=ga.ga",
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: "cert:x509:ca99?cn=goo.goo",
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims:       nil,
	}
	appendChallengeResponse(t, cr, cresp1)
	appendChallengeResponse(t, cr, cresp2)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "ca0,ca99", adom) // In this case you can have multiple "domains" ?
}

func TestSelectDSPrefixMultipleExternal(t *testing.T) {
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	cresp1 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtRSA,
	}
	cresp2 := &zds.ChallengeResponse{
		RespSpec: AuthAttrExtOpenID,
	}

	cr := &vsapi.ConnectRequest{
		ConnectionID: 1,
		Claims:       nil,
	}
	appendChallengeResponse(t, cr, cresp1)
	appendChallengeResponse(t, cr, cresp2)

	adom, err := svc.SelectValidateDSPrefix(p, cr)
	require.Nil(t, err)
	require.Equal(t, "simplev", adom)
}

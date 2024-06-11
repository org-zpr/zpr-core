package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/missing/zpl/compiler"
	"zpr.org/vs/pkg/missing/zpl/fs"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/polio"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/snio/zds"
	"zpr.org/vs/pkg/vservice/auth"
)

type TRevokingSvc struct{}

func (tr *TRevokingSvc) ProposeClearAllRevokes(string)                 {}
func (tr *TRevokingSvc) ListRevocationKeysFor(string) []string         { return nil }
func (tr *TRevokingSvc) GetRevoke(string) *auth.Revoke                 { return nil }
func (tr *TRevokingSvc) ProposeRevokeCredential(pver, cred string)     {}
func (tr *TRevokingSvc) ProposeRevokeAuthority(pver, credIdent string) {}

var pyaml = `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            n0i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.foo, fox]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland system
          components:
`

func TestAuthenticateHappyPathInternOnly(t *testing.T) {
	t.Skip("waiting on compiler port")
	var err error

	addr := netip.MustParseAddr("fc00:3001::1234")
	// revoker := &TRevokingSvc{}
	pkey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.Nil(t, err)

	a := auth.NewAuthenticator(logr.NewTestLogger(), addr, 10*time.Minute, "node0", pkey)

	var plcy *policy.Policy
	var ppol *polio.Policy
	{
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(pyaml))
		fst.AddFile("/ca0-cert.pem", []byte(caCertPEM))

		opts := &compiler.CompileOpts{
			Revision: "t01",
			Verbose:  true,
		}
		ppol, err = compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, ppol)
	}

	plcy = policy.NewPolicyFromPol(ppol, logr.NewTestLogger())
	a.InstallPolicy(1, 1, plcy)

	clientAddr := netip.MustParseAddr("fc00:3001::4567")

	unauthClaims := make(map[string]string)

	chal := new(zds.Challenge)
	{
		ts := time.Now().Format(time.RFC3339)
		rawNonce := make([]byte, 1024)
		snauth.NewNonce(rawNonce)
		chal.Spec = snauth.AuthChallengeV1
		chal.Timestamp = ts
		chal.Nonce = rawNonce
	}

	conf := map[string]string{
		"key_data":  base64.StdEncoding.EncodeToString([]byte(agentKeyPEM)),
		"cert_data": base64.StdEncoding.EncodeToString([]byte(agentCertPEM)),
	}

	unauthClaims["ca0.x509.cn"] = "ma.hatma"
	rsam := snauth.NewRSAv2()
	chalResp, err := rsam.Respond(conf, chal, 0)
	require.Nil(t, err)

	aOK, err := a.Authenticate("", clientAddr, chal, chalResp, unauthClaims)
	require.Nil(t, err)
	require.NotNil(t, aOK)

	require.Len(t, aOK.Identities, 1) // Identity is a JWT token
	require.True(t, aOK.Expire.After(time.Now()))
	require.Len(t, aOK.Credentials, 2) // == (CA_CERT_ID, JWT_ID)
	require.Len(t, aOK.Claims, 1)
	require.Contains(t, aOK.Claims, "ca0.x509.cn")
	require.Equal(t, "ma.hatma", aOK.Claims["ca0.x509.cn"].V)
	require.Len(t, aOK.Prefixes, 1)
	require.Equal(t, []string{"ca0"}, aOK.Prefixes)
}

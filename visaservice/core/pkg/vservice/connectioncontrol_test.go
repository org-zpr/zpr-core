package vservice_test

/* DISABLED UNTIL WE SORT OUT COMPILER

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
	authcert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)
	// Minimal config:
	vc := vservice.VSIConfig{
		CN:                    "vs.zpr",
		VSAddr:                netip.MustParseAddr(vservice.VisaServiceAddress),
		Log:                   llog,
		HopCount:              uint(99),
		BootstrapAuthDuration: 1 * time.Hour,
		AuthorityCert:         authcert,
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
	svc, p := makeVSWithPolicy(t, basicPolicyTwoDS)

	blob := auth.NewZdpSelfSignedBlobUnsiged("ss.spacelaser.net", []byte("challenge-bytes-are-here"))

	// don't bother signing it.

	adom, err := svc.SelectValidateDSPrefix(p, blob)
	require.Nil(t, err)
	require.Equal(t, auth.AUTH_PREFIX_BOOTSTRAP, adom)
}

*/

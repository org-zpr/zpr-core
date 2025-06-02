package vservice_test

/* DISABLED UNTIL WE SORT OUT COMPILER

const ca0cert = `
-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIUewwSCpOmNA0WLX+ZyVL5zf18RCEwDQYJKoZIhvcNAQEL
BQAwgZ0xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNQTEPMA0GA1UEBwwGQm9zdG9u
MRAwDgYDVQQKDAdTVVJFTkVUMRUwEwYDVQQLDAxDZXJ0aWZpY2F0ZXMxJzAlBgNV
BAMMHnRlc3RuZXQtcm9vdC1jYS5zcGFjZWxhc2VyLm5ldDEeMBwGCSqGSIb3DQEJ
ARYPcm9vdC1jYUBzdXJlbmV0MB4XDTIwMDUwNzE5NTIyMVoXDTI1MDUwNjE5NTIy
MVowgZ0xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNQTEPMA0GA1UEBwwGQm9zdG9u
MRAwDgYDVQQKDAdTVVJFTkVUMRUwEwYDVQQLDAxDZXJ0aWZpY2F0ZXMxJzAlBgNV
BAMMHnRlc3RuZXQtcm9vdC1jYS5zcGFjZWxhc2VyLm5ldDEeMBwGCSqGSIb3DQEJ
ARYPcm9vdC1jYUBzdXJlbmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAx3sFKZdvvE7P37WWvUeBwGCKi/Z8szy7eX84u9kK3o7SpZ4LQB96Z9av8fb4
g083prfVqd6IjzaM0SrC8n+QpsSsGxinMTPPDG0PBHcRhdPwUeKfRCKrpUtx9X1z
7EKwr7Q8QA7xyPXX2UTDaEb0gM/garD1oOfmcbZpzyp0E5RLYqBBccP+1S6NWO0p
61J9ZZUIOPy2usPT6Npo+0uTuBsN/6e8s0YKb59WKHNPsizyTYN81j0/JlA0Z262
J8/RL/C9h9bwwMQX7OOfkDPyn4FW7CyxHmpZ3DHTNGXhNNLMs0DWbLlcAwsCIqz2
MElbNdnbJ+v0FY9HnRVqo6DgoQIDAQABo1MwUTAdBgNVHQ4EFgQU4R/rOzDGggMg
CK8J/uY8P+Qt0SMwHwYDVR0jBBgwFoAU4R/rOzDGggMgCK8J/uY8P+Qt0SMwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFyiQ/Ev/IIF9Z/hkf8uN
vVa5hv7oBfJPmiVLWp2TwFD0A/sV5DTxjTEkkBpBzCSHYh/8eQfnwipz3VfdfFhd
+BzNzVazuMlMpp5ULSLHuOWGB0NXwDYTLjDalPCp2OAHhDDvSJZQvZUWe+Q/i7j3
jpXLbb8PDyz54iZMxc2eC0i1FWETLYEb82dSwiOcJgwvnaQmzQrV/cs/yzqHhYNG
VmH5KdzmEnjGOW26yuYBEEMKMHNQDyvV/l6hg4ICjFu9NDz5+4BHiK5LeYmcAKDB
5V+MXCHvw4yhaPTFAdgQ827SFmrkWAf8lMkqFDwO1UxFRffi8Y9YaOY7GY0P5WMb
Kw==
-----END CERTIFICATE-----
`

const simplevCert = `
-----BEGIN CERTIFICATE-----
MIIDpjCCAo6gAwIBAgIJALmfRuDUHz3ZMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJLWTETMBEGA1UEBwwKTG91aXN2aWxsZTEQMA4GA1UE
CgwHU3VyZW5ldDENMAsGA1UECwwETmV0czEdMBsGA1UEAwwUYXV0aDAuc3BhY2Vs
YXNlci5uZXQwHhcNMjAxMDA2MjExODUzWhcNMjIxMDA2MjExODUzWjBvMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxEzARBgNVBAcMCkxvdWlzdmlsbGUxEDAOBgNV
BAoMB1N1cmVuZXQxDTALBgNVBAsMBE5ldHMxHTAbBgNVBAMMFGF1dGgwLnNwYWNl
bGFzZXIubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqk6kBQuk
/oRGebkGUIoI5s0lZhfnLzBggnETBkCSk+CMd1nBtB2v70ugsjU5wUCsAo8pwdXU
X33BLaJNKYOP7yzHIDonTEvvssVNX1UnvmZxMlDVqJ4lJlismBzJARwirbphUesk
s/K1S2YLwXITXeB4/ojhNDto0beBRbz5D8h5EXYULCw2gZIeQ+BCQVBSkNVwzhMq
yghxzzCyzuhvIpqHl7th+dcTtfHoT6XaHVS5meKxE23UIGi1wCRxSRzSv/HzrYDP
bjtj2ySx1efrEy5sxMq8ZmPU+qN15PPnzX1digfx6HJ/blT204hDg7lwFBUebvF0
7NumNbgi2+O9WQIDAQABo0UwQzALBgNVHQ8EBAMCBDAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwDQYJKoZIhvcN
AQELBQADggEBAFtEFs2ZinunEMhS/I3liCQ6Lb+CpW+GPQzhigznEYqRYJ+euTGy
V2ub0tMAmd2qr9IU5bn3w3ecN29V7v0WcmN+Itd4A7ulexBUav5NfyeUk6qgqZZv
SUtuvlU0kNU3Hi8YoCxEwyn4Mdi6O6Qohgks73QAnYCl76gBgdGfbWJ9Fc55Ig9l
F7cFZA5UQOthoEoh6w7A+fcjOLMOINZTV6l7LRR+pg0OT8p8t7bHqLvfuStC5oav
uDXDh6/V3rxvQoV3+YrEIm5Snpjh8s5p1cv0ICB5ORIh7KYsIsrbwhKCxwMwsjLq
TmgyWDoy+cjbuozxQCbf3fbrq/zRyC5Y288=
-----END CERTIFICATE-----
`

func mustUnmarshalVisa(pb []byte) *vsio.Visa {
	var visaObj vsio.Visa
	err := proto.Unmarshal(pb, &visaObj)
	if err != nil {
		panic(err)
	}
	return &visaObj
}

type TestAS struct{}

func (tas *TestAS) Authenticate(domain string, epID netip.Addr,
	blob auth.Blob, claims map[string]string) (*auth.AuthenticateOK, error) {
	return nil, fmt.Errorf("Authenticate not implemented")
}

func (tas *TestAS) Query(*zds.QueryRequest) (*zds.QueryResponse, error) {
	return nil, fmt.Errorf("Query not implemented")
}
func (tas *TestAS) SetCurrentPolicy(cfg uint64, pol *policy.Policy) error {
	return fmt.Errorf("SetCurrentPolicy not implemented on test auth service")
}

func (tas *TestAS) RevokeAuthority(string) error               { return nil }
func (tas *TestAS) RevokeCredential(string) error              { return nil }
func (tas *TestAS) RevokeCN(string) error                      { return nil }
func (tas *TestAS) ClearAllRevokes() uint32                    { return 0 }
func (tas *TestAS) InstallPolicy(uint64, byte, *policy.Policy) {}
func (tas *TestAS) ActivateConfiguration(uint64, byte)         {}
func (tas *TestAS) RemoveServiceByPrefix(_ string) int         { return 0 }

func (tas *TestAS) AddDatasourceProvider(_ string, _ netip.Addr, _ uint64) error {
	return nil
}

func minVSI(t *testing.T, hopcount uint, alog logr.Logger) *vservice.VSIConfig {
	// Minimal config:
	authcert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)
	return &vservice.VSIConfig{
		Log:                   alog,
		CN:                    "vs.zpr",
		VSAddr:                netip.MustParseAddr(vservice.VisaServiceAddress),
		HopCount:              hopcount,
		AllowInvalidPeerAddr:  true,
		BootstrapAuthDuration: 1 * time.Hour,
		AuthorityCert:         authcert,
	}
}

// Helper to createa a TCP SYN packet.
func createPacket(pktbuf gopacket.SerializeBuffer, src, dst netip.Addr, srcPort, dstPort uint16) {
	// pktbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	payload := gopacket.Payload([]byte{1, 2, 3, 4})
	payload.SerializeTo(pktbuf, opts)

	tcph := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcph.SerializeTo(pktbuf, opts)

	iph := &layers.IPv6{
		Version:    6,
		SrcIP:      net.IP(src.AsSlice()),
		DstIP:      net.IP(dst.AsSlice()),
		NextHeader: layers.IPProtocolTCP,
	}
	iph.SerializeTo(pktbuf, opts)
}

// Test that the a duration constraint set in policy makes it all the way to
// the visa expiration time.
func TestRequestVisaWithConstraint(t *testing.T) {
	alog := logr.NewTestLogger()

	vc := minVSI(t, 99, alog)

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	naddr := netip.MustParseAddr("fc00:3001:1::11")
	apiKey, _ := svc.BackDoorInstallAPIKeyForUnitTest(naddr, "n0", fmt.Sprintf("127.0.0.1:%d", vservice.VSSDefaultPort))

	// Just add a web service to the node.
	// In the future this will need to be re-worked since node config will be separate.
	pyaml := `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - [ca0.foo, eq, fox]
            admin_attrs:
              - [ca0.foo, eq, fee]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:1::11"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"
              services: [http]
              policies: # ERROR - not that this policy applies to all services on the node.
                - desc: web access
                  conditions:
                     - desc: foo fee
                       attrs:
                          - [ca0.foo, eq, fee]
                  constraints:
                    duration: 90s

          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(pyaml))
		fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)

		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	taddr := netip.MustParseAddr("fc00:3001::9")
	saddr := netip.MustParseAddr("fc00:3001:1::10")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, naddr, 30000, 80)

	// Prior to requesting a visa, we need to have told visa service about the
	// adapter(s).
	{
		claims := map[string]*actor.ClaimV{
			"ca0.foo": &actor.ClaimV{V: "fee", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(taddr, saddr, naddr, claims, time.Now().Add(5*time.Minute))
	}

	res, err := svc.RequestVisa(context.Background(), apiKey, taddr.AsSlice(), 6, pktbuf.Bytes())
	require.Nil(t, err)
	require.Equal(t, "", res.GetReason())
	require.Equal(t, vsapi.StatusCode_SUCCESS, res.Status)

	require.NotNil(t, res.GetVisa().Visa)
	visaObj := res.GetVisa().Visa

	require.Less(t, visaObj.Expires, time.Now().Add(95*time.Second).Unix()*1000)

	err = svc.DeRegister(context.Background(), apiKey)
	require.Nil(t, err)

}

func TestRequestVisaDupes(t *testing.T) {
	alog := logr.NewTestLogger()

	// Minimal config:
	vc := minVSI(t, 99, alog)

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	naddr := netip.MustParseAddr("fc00:3001:1::11")
	apiKey, _ := svc.BackDoorInstallAPIKeyForUnitTest(naddr, "n0", fmt.Sprintf("127.0.0.1:%d", vservice.VSSDefaultPort))

	// Just add a web service to the node.
	// In the future this will need to be re-worked since node config will be separate.
	pyaml := `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - [ca0.foo, eq, fox]
            admin_attrs:
              - [ca0.foo, eq, fee]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:1::11"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"
              services: [http]
              policies: # ERROR - not that this policy applies to all services on the node.
                - desc: web access
                  conditions:
                     - desc: foo fee
                       attrs:
                          - [ca0.foo, eq, fee]
                  constraints:
                    duration: 90s

          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(pyaml))
		fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)

		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	taddr := netip.MustParseAddr("fc00:3001::9")

	saddr := netip.MustParseAddr("fc00:3001:1::10")
	daddr := netip.MustParseAddr("fc00:3001:1::11")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, daddr, 30000, 80)

	{
		claims := map[string]*actor.ClaimV{
			"ca0.foo": &actor.ClaimV{V: "fee", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(taddr, saddr, naddr, claims, time.Now().Add(5*time.Minute))
	}

	var resp1, resp2 *vsapi.VisaResponse

	{
		resp1, err = svc.RequestVisa(context.Background(), apiKey, taddr.AsSlice(), 6, pktbuf.Bytes())
		require.Nil(t, err)
		require.Equal(t, vsapi.StatusCode_SUCCESS, resp1.Status)
	}
	require.NotNil(t, resp1.GetVisa().Visa)

	// Now request again. For now the visa service will happily create another
	// visa. Possibly we want to prevent this, but one tricky issue is that the
	// visa service must allow new visas to be created that extend the lifetime
	// but are otherwise the same.
	{
		resp2, err = svc.RequestVisa(context.Background(), apiKey, taddr.AsSlice(), 6, pktbuf.Bytes())
		require.Nil(t, err)
		require.Equal(t, vsapi.StatusCode_SUCCESS, resp2.Status)
	}
	require.NotNil(t, resp2.GetVisa().Visa)

	v1 := resp1.Visa.Visa
	require.Nil(t, err)
	v2 := resp2.Visa.Visa
	require.Nil(t, err)

	require.NotEqual(t, v1.IssuerID, v2.IssuerID) // New unique issuer IDs
}

// Ensure that if actor auth has expired, no visa is issued.
func TestAuthExpireNoVisa(t *testing.T) {
	alog := logr.NewTestLogger()

	// Minimal config:
	vc := minVSI(t, 99, alog)

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	naddr := netip.MustParseAddr("fc00:3001:1::11")
	apiKey, _ := svc.BackDoorInstallAPIKeyForUnitTest(naddr, "n0", fmt.Sprintf("127.0.0.1:%d", vservice.VSSDefaultPort))

	// Just add a web service to the node.
	// In the future this will need to be re-worked since node config will be separate.
	pyaml := `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - [ca0.foo, eq, fox]
            admin_attrs:
              - [ca0.foo, fee]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              address: "fc00:3001:1::11"
              provider:
                - [ca0.x509.cn, n0.internal]
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"
              services: [http]
              policies:
                - desc: web access
                  conditions:
                    - name: foo fee
                      attrs:
                        - [ca0.foo, fee]
                      constraints:
                        duration: 90s
          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]
        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(pyaml))
		fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)

		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	taddr := netip.MustParseAddr("fc00:3001::9")

	saddr := netip.MustParseAddr("fc00:3001:1::10")
	daddr := netip.MustParseAddr("fc00:3001:1::11")
	pktbuf := gopacket.NewSerializeBuffer()
	createPacket(pktbuf, saddr, daddr, 30000, 80)

	{
		claims := map[string]*actor.ClaimV{
			"ca0.foo": &actor.ClaimV{V: "fee", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(taddr, saddr, naddr, claims, time.Now().Add(-time.Hour)) // <--- note expired
	}

	res, err := svc.RequestVisa(context.Background(), apiKey, taddr.AsSlice(), 6, pktbuf.Bytes())
	require.Nil(t, err)
	require.Equal(t, vsapi.StatusCode_FAIL, res.Status)
	require.Equal(t, "auth expired", res.GetReason())
}

func TestVisaServiceVisasExtended(t *testing.T) {
	pyaml := `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            dock: n0
            provider:
              - [ca0.foo, eq, fox]
            admin_attrs:
              - [ca0.foo, eq, fee]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [ca0.x509.cn, n0.internal]
              address: "fc00:3001:1::11"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"
            n1:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1b"
              provider:
                - [ca0.x509.cn, n1.internal]
              address: "fc00:3001:1::12"
              interfaces:
                i0:
                  netaddr: "n1.spacelaser.net:5000"
          datasources:
            ca0:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
        `

	alog := logr.NewTestLogger()

	vsaddr := netip.MustParseAddr(vservice.VisaServiceAddress)
	vssListenAddr := fmt.Sprintf("127.0.0.1:%d", vservice.VSSDefaultPort)

	// Minimal config:
	vc := minVSI(t, 99, alog)
	vc.ReauthBumpTimeOverride = 10 * time.Second // reduce from default of 5 minutes

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	n0addr := netip.MustParseAddr("fc00:3001:1::11")
	n1addr := netip.MustParseAddr("fc00:3001:1::12")

	apiKey, err := svc.BackDoorInstallAPIKeyForUnitTest(n0addr, "n0", vssListenAddr)
	require.Nil(t, err)

	// Node n1 has very short auth lifetime. So any visas created for it will be short too.
	_, err = svc.BackDoorInstallAPIKeyForUnitTestExp(n1addr, "n1", time.Now().Add(10*time.Second), vssListenAddr) // <--- note expiry in 10s
	require.Nil(t, err)

	vs_claims := make(map[string]*actor.ClaimV)
	vs_claims["ca0.foo"] = &actor.ClaimV{V: "fox", Exp: time.Now().Add(time.Hour)}
	err = svc.BackDoorConnectSvcAdapter(vsaddr, vsaddr, n0addr, vs_claims, []string{"$$zpr/visaservice", "/zpr/$$zpr/visaservice"}, time.Now().Add(time.Hour))
	require.Nil(t, err)

	go svc.Start(netip.MustParseAddr("127.0.0.1"), vservice.VisaServicePort)
	defer svc.Stop()

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(pyaml))
		fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)

		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
		require.Nil(t, err)
	}

	{
		client110 := netip.MustParseAddr("fc00:3001:1::10")
		client110ta := netip.MustParseAddr("fc00:3001::10")
		claims := map[string]*actor.ClaimV{
			"ca0.foo": &actor.ClaimV{V: "fee", Exp: time.Now().Add(time.Hour)},
		}
		svc.BackDoorConnectAdapter(client110ta, client110, n1addr, claims, time.Now().Add(time.Hour))
	}

	// So the visas for node n1 will be expiring very soon, as soon as the visa housekeeping runs it
	// should try to create a successor visa.

	svc.RunPeriodicHousekeepingNow() // blocking
	time.Sleep(200 * time.Millisecond)

	presp, err := svc.Poll(apiKey) // polling for n0
	require.Nil(t, err)
	require.NotEmpty(t, presp.Visas)
	require.Empty(t, presp.Revocations)

	// All the visas that the system has tried to send directly have failed,
	// so they are all sitting in the buffer.
	require.Equal(t, 5, len(presp.Visas))

	// Really, node n0 should only get visas related to it.
	expectSources := []string{
		n0addr.String(), // :11
		vsaddr.String(), // 3003::1
	}

	for _, v := range presp.Visas {
		require.Greater(t, v.GetHopCount(), int32(0))

		newV := v.Visa

		require.NotNil(t, newV)
		require.NotNil(t, newV.GetSource())
		require.NotNil(t, newV.GetDest())

		// Either source or dest must be our polling node (n0)
		require.Contains(t, []string{net.IP(newV.GetSource()).String(), net.IP(newV.GetDest()).String()}, n0addr.String())

		require.Contains(t, expectSources, mustAddrFromSlice(newV.GetSource()).String())
	}
}

func mustAddrFromSlice(s []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(s)
	if !ok {
		panic("failed to parse netip.Addr from slice")
	}
	return a
}

*/

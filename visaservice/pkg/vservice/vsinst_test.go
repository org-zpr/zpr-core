package vservice_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/missing/zpl/compiler"
	"zpr.org/vs/pkg/missing/zpl/fs"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snio/vsio"
	"zpr.org/vs/pkg/snio/zds"
	"zpr.org/vs/pkg/vservice"
	"zpr.org/vs/pkg/vservice/auth"

	snip "zpr.org/vs/pkg/ip"
)

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

func ipTrafficToSnioPacketDesc(t *snip.Traffic) *vsio.PacketDesc {
	return &vsio.PacketDesc{
		Source:   t.SrcAddr.AsSlice(),
		Dest:     t.DstAddr.AsSlice(),
		Protocol: t.Proto.Num(),
		SrcPort:  uint32(t.SrcPort),
		DstPort:  uint32(t.DstPort),
		Flags:    t.Flags,
		IcmpType: uint32(t.ICMPType),
		IcmpCode: uint32(t.ICMPCode),
		IcmpAddr: t.ICMPTargetAddress.AsSlice(),
		Size:     uint32(t.Size),
	}
}

// TestDS is a test implementation of DirectoryService used by visaservice.
type TestDS struct {
	recs map[string]*vsio.Agent
}

// Implements DirectoryService interface
func (tds *TestDS) AgentAtContactAddr(a netip.Addr) (*vsio.Agent, error) {
	rec, ok := tds.recs[a.String()]
	if !ok {
		return nil, fmt.Errorf("agent record not found: %v", a.String())
	}
	return rec, nil
}

// Implements DirectoryService interface
func (tds *TestDS) ZPRAddrForService(string) []netip.Addr {
	panic("TestDS.ZPRAddrForService not implemented")
}

type TestAS struct{}

func (tas *TestAS) Authenticate(domain string, epID netip.Addr,
	chal *zds.Challenge, chalResp []*zds.ChallengeResponse, claims map[string]string) (*auth.AuthenticateOK, error) {
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
func (tas *TestAS) InstallPolicy(uint64, byte, *policy.Policy) {}
func (tas *TestAS) ActivateConfiguration(uint64, byte)         {}
func (ts *TestAS) RemoveServiceByPrefix(_ string) int          { return 0 }

func (ts *TestAS) AddDatasourceProvider(_ string, _ netip.Addr, _ uint64) error {
	return nil
}

func minVSI(t *testing.T, hopcount uint, alog logr.Logger, ds vservice.DirectoryService) *vservice.VSIConfig {
	// Minimal config:
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	return &vservice.VSIConfig{
		Log:                  alog,
		HopCount:             hopcount,
		AgentSigningKey:      pk,
		AllowInvalidPeerAddr: true,
		Directory:            ds,
	}
}

// Test that the a duration constraint set in policy makes it all the way to
// the visa expiration time.
func TestRequestVisaWithConstraint(t *testing.T) {
	t.Skip("waiting on compiler port")
	alog := logr.NewTestLogger()

	testDS := &TestDS{
		recs: map[string]*vsio.Agent{
			"fc00:3001:1::10": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339), // These auth expire times are used as part of visa expiration calculation.
				AuthClaims:  map[string]*vsio.AClaim{"ca0.foo": &vsio.AClaim{Cval: "fee", Exp: time.Now().Add(time.Hour).Unix()}},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::10").AsSlice(),
			},
			"fc00:3001:1::11": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				Provides:    []string{"/zpr/n0"},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::11").AsSlice(),
			},
		},
	}

	vc := minVSI(t, 99, alog, testDS)

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	// Registering is not required under unit testing, but this is here just to catch a
	// bug in the function.
	regreq := &vsio.VSRegisterRequest{
		NodeAddr: netip.MustParseAddr("fc00:3001:1::11").AsSlice(),
	}
	_, err = svc.Register(context.Background(), regreq)
	require.Nil(t, err)

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

	taddr := net.ParseIP("fc00:3001::9")
	td := &snip.Traffic{
		SrcAddr: netip.MustParseAddr("fc00:3001:1::10"),
		DstAddr: netip.MustParseAddr("fc00:3001:1::11"),
		Proto:   snip.ProtocolTCP,
		SrcPort: 30000,
		DstPort: 80, // WEB request
		Connect: true,
		Syn:     true,
		Size:    64,
	}
	req := &vsio.VSRequest{
		SrcTetherAddr: taddr,
		Traffic:       ipTrafficToSnioPacketDesc(td),
	}
	res, err := svc.RequestVisa(context.Background(), req)
	require.Nil(t, err)
	require.True(t, res.Success)

	require.NotNil(t, res.GetVisa().GetVisa())
	require.Less(t, res.GetVisa().Visa.Expires, time.Now().Add(95*time.Second).Unix()*1000)

	// Registering/Deregistering is not required under unit testing, but this is here just to catch a
	// bug in the function.
	deregreq := &vsio.VSDeRegisterRequest{
		NodeAddr: netip.MustParseAddr("fc00:3001:1::11").AsSlice(),
	}
	_, err = svc.DeRegister(context.Background(), deregreq)
	require.Nil(t, err)

}

func TestRequestVisaDupes(t *testing.T) {
	t.Skip("waiting on compiler port")
	alog := logr.NewTestLogger()

	testDS := &TestDS{
		recs: map[string]*vsio.Agent{
			"fc00:3001:1::10": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339), // These auth expire times are used as part of visa expiration calculation.
				AuthClaims:  map[string]*vsio.AClaim{"ca0.foo": &vsio.AClaim{Cval: "fee", Exp: time.Now().Add(time.Hour).Unix()}},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::10").AsSlice(),
			},
			"fc00:3001:1::11": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				Provides:    []string{"/zpr/n0"},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::11").AsSlice(),
			},
		},
	}

	// Minimal config:
	vc := minVSI(t, 99, alog, testDS)

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

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

	taddr := net.ParseIP("fc00:3001::9")
	td := &snip.Traffic{
		SrcAddr: netip.MustParseAddr("fc00:3001:1::10"),
		DstAddr: netip.MustParseAddr("fc00:3001:1::11"),
		Proto:   snip.ProtocolTCP,
		SrcPort: 30000,
		DstPort: 80, // WEB request
		Connect: true,
		Syn:     true,
		Size:    64,
	}

	var resp1, resp2 *vsio.VSResponse

	{
		req := &vsio.VSRequest{
			SrcTetherAddr: taddr,
			Traffic:       ipTrafficToSnioPacketDesc(td),
		}
		resp1, err = svc.RequestVisa(context.Background(), req)
		require.Nil(t, err)
		require.True(t, resp1.Success)
	}
	require.NotNil(t, resp1.GetVisa().GetVisa())

	// Now request again. For now the visa service will happily create another
	// visa. Possibly we want to prevent this, but one tricky issue is that the
	// visa service must allow new visas to be created that extend the lifetime
	// but are otherwise the same.
	{
		req := &vsio.VSRequest{
			SrcTetherAddr: taddr,
			Traffic:       ipTrafficToSnioPacketDesc(td),
		}
		resp2, err = svc.RequestVisa(context.Background(), req)
		require.Nil(t, err)
		require.True(t, resp2.Success)
	}
	require.NotNil(t, resp2.GetVisa().GetVisa())
	require.NotEqual(t, resp1.GetVisa().Visa.IssuerId, resp2.GetVisa().Visa.IssuerId) // New unique issuer IDs
}

// Ensure that if agent auth has expired, no visa is issued.
func TestAuthExpireNoVisa(t *testing.T) {
	t.Skip("waiting on compiler port")
	alog := logr.NewTestLogger()

	testDS := &TestDS{
		recs: map[string]*vsio.Agent{
			"fc00:3001:1::10": {
				AuthExpires: time.Now().Add(-1 * time.Hour).Format(time.RFC3339), // EXPIRED !
				AuthClaims:  map[string]*vsio.AClaim{"ca0.foo": &vsio.AClaim{Cval: "fee", Exp: time.Now().Add(time.Hour).Unix()}},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::10").AsSlice(),
			},
			"fc00:3001:1::11": {
				AuthExpires: time.Now().Add(-1 * time.Hour).Format(time.RFC3339), // EXPIRED !
				Provides:    []string{"/zpr/n0"},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::11").AsSlice(),
			},
		},
	}

	// Minimal config:
	vc := minVSI(t, 99, alog, testDS)

	// TODO: This initializer is insane. Too hard to test, need to refactor.
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

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

	taddr := net.ParseIP("fc00:3001::9")
	td := &snip.Traffic{
		SrcAddr: netip.MustParseAddr("fc00:3001:1::10"),
		DstAddr: netip.MustParseAddr("fc00:3001:1::11"),
		Proto:   snip.ProtocolTCP,
		SrcPort: 30000,
		DstPort: 80, // WEB request
		Connect: true,
		Syn:     true,
		Size:    64,
	}
	req := &vsio.VSRequest{
		SrcTetherAddr: taddr,
		Traffic:       ipTrafficToSnioPacketDesc(td),
	}

	res, err := svc.RequestVisa(context.Background(), req)
	require.Nil(t, err)
	require.False(t, res.Success)
	require.Equal(t, "auth expired", res.ErrorMsg)
}

func TestVisaServiceVisasExtended(t *testing.T) {
	t.Skip("waiting on compiler port")
	alog := logr.NewTestLogger()

	vsaddr := netip.MustParseAddr(vservice.VisaServiceAddress) // fc00:3003::1
	n0addr := netip.MustParseAddr("fc00:3001:1::11")
	n1addr := netip.MustParseAddr("fc00:3001:1::12")

	testDS := &TestDS{
		recs: map[string]*vsio.Agent{
			vservice.VisaServiceAddress: {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				Provides: []string{
					"$$zpr/visaservice",
					"/zpr/$$zpr/visaservice", // TODO: This needs to be fixed -- the name should be just /zpr/visaservice I think.
				},
				AuthClaims: map[string]*vsio.AClaim{
					agent.KAttrVisaServiceAdapter: {Cval: "true", Exp: time.Now().Add(time.Hour).Unix()},
				},
				TetherAddr: vsaddr.AsSlice(), // Note: adapter gets visa service address too!
			},
			"fc00:3001:1::10": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				AuthClaims:  map[string]*vsio.AClaim{"ca0.foo": &vsio.AClaim{Cval: "fee", Exp: time.Now().Add(time.Hour).Unix()}},
				TetherAddr:  netip.MustParseAddr("fc00:3001:1::10").AsSlice(),
			},
			"fc00:3001:1::11": {
				AuthExpires: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				Provides:    []string{"/zpr/n0"},
				AuthClaims: map[string]*vsio.AClaim{
					"zpr.role": {Cval: "node", Exp: time.Now().Add(time.Hour).Unix()},
				},
				TetherAddr: n0addr.AsSlice(),
			},
			"fc00:3001:1::12": {
				AuthExpires: time.Now().Add(10 * time.Second).Format(time.RFC3339), // <-- note this is about to expire
				Provides:    []string{"/zpr/n1"},
				AuthClaims: map[string]*vsio.AClaim{
					"zpr.role": {Cval: "node", Exp: time.Now().Add(time.Hour).Unix()},
				},
				TetherAddr: n1addr.AsSlice(),
			},
		},
	}

	// Minimal config:
	vc := minVSI(t, 99, alog, testDS)
	vc.NodeName = "n0.spacelaser.net"
	vc.ReauthBumpTimeOverride = 10 * time.Second // reduce from default of 5 minutes

	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})

	// TODO: What is this for? The visa service has well known address (or is from a range of them).
	// I beleive for time being, the visa service gets static IP _AND_ the adapter for the visa service
	// takes that address aswell (like a node would).
	svc.SetLocalAddr(vsaddr)

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
              - [ca0.foo, fee]
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

	// Request a visa-service visa:
	td := &vsio.PacketDesc{
		Source:   n1addr.AsSlice(),
		Dest:     vsaddr.AsSlice(),
		Protocol: snip.ProtocolTCP.Num(),
		SrcPort:  vservice.VisaServicePort,
		DstPort:  vservice.VisaServicePort,
		Flags:    0x0002, // SYN
	}
	req := &vsio.VSRequest{
		SrcTetherAddr: n1addr.AsSlice(),
		Traffic:       td,
	}
	res, err := svc.RequestVisa(context.Background(), req)
	require.Nil(t, err)
	require.Equal(t, "", res.ErrorMsg)
	require.True(t, res.Success)

	require.NotNil(t, res.GetVisa().GetVisa())
	expt := vsio.VToTime(res.GetVisa().Visa.GetExpires())
	require.True(t, time.Until(expt) < time.Minute) // should be very short TTL
	oldv := res.GetVisa().GetVisa()

	// So the visa will be expiring very soon, as soon as the visa housekeeping runs it
	// should try to create a successor visa.

	svc.AddNode(n1addr)              // creates a 'mailbox' for the node
	svc.RunPeriodicHousekeepingNow() // blocking

	preq := vsio.VSPollRequest{DockAddr: n1addr.AsSlice()}
	presp, err := svc.Poll(context.Background(), &preq)
	require.Nil(t, err)
	require.False(t, presp.GetMore())
	require.NotEmpty(t, presp.GetVisas())
	require.Empty(t, presp.GetRevokes())

	// Should be a single visa for us:
	require.Equal(t, 1, len(presp.GetVisas()))

	require.Greater(t, presp.GetVisas()[0].GetHopCount(), uint32(0))
	newV := presp.GetVisas()[0].GetVisa()
	require.NotNil(t, newV)
	require.NotNil(t, newV.GetSource())
	require.NotNil(t, newV.GetDest())

	require.Equal(t, vsaddr, mustAddrFromSlice(newV.GetDest()))
	require.Equal(t, n1addr, mustAddrFromSlice(newV.GetSource()))
	require.Greater(t, newV.IssuerId, oldv.IssuerId)
}

func mustAddrFromSlice(s []byte) netip.Addr {
	a, ok := netip.AddrFromSlice(s)
	if !ok {
		panic("failed to parse netip.Addr from slice")
	}
	return a
}

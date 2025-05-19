package compiler_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/fs"
)

const (
	VisaServiceAddress = "fd5a:5052::1"
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

const ca1cert = `
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIUWP3IYu6Y6KOuRHEVs06y8yML+JIwDQYJKoZIhvcNAQEL
BQAwZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3Zp
bGxlMQswCQYDVQQKDAJBSTEMMAoGA1UECwwDWlBSMRswGQYDVQQDDBJjYTEuc3Bh
Y2VsYXNlci5uZXQwHhcNMjIwNDI4MTg1ODQ5WhcNMjcwNDI3MTg1ODQ5WjBnMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCS1kxEzARBgNVBAcMCkxvdWlzdmlsbGUxCzAJ
BgNVBAoMAkFJMQwwCgYDVQQLDANaUFIxGzAZBgNVBAMMEmNhMS5zcGFjZWxhc2Vy
Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtmaq85AzmUrJxP
foTKLzdwgTpr6C7szxNMylusH/W6GL/mkMh+wa7DT9BV95ZW0BFPZCBwuMwiausw
c51v1f2uFT+IV1MbUWZ3wfNkVG7GcucDJZTwG2BJ08tZM1XcOz+tPL+BN3+xcA8a
1a6Wy/fynyaWf+on16mYR4GNGwKVXyagP5j+loW9s27vp2NWOxzVUTvW0afbZlxx
2EGpeote3OcgImn5ltHXCk5Gp6oTEw7dTQ0Hukf2nJ/GquYrEVFHW6NOApJlHwM1
8ifH6sMST2QLKWibwDHDvr0ebZH7YTWcpUlK5/dJEXGSTYNJXEoYUFQmWfTpyDnt
wWaMOFkCAwEAAaNTMFEwHQYDVR0OBBYEFM4wY91a3vUXdEviaU7RmbiythFCMB8G
A1UdIwQYMBaAFM4wY91a3vUXdEviaU7RmbiythFCMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBABFGl+B0JnVhLIg7oN7Nbg/DZOODxNLCrdNwV4ZX
g+/HTTEVuL7TFgkDouTNjTzBFJsiFhcii1HJ7tizdSAYSu5JiAny7nAi0lFhpIjB
YtZNY8ZuGMW58eFhOfhS1ZXGLLT7RxmlevpASFTZxYW6ILsqBA4eA7IiPAPha3j4
/fLVtDsuHP+lrRKthVOBftCR6PCrLGP986vDkeAgVsKD5bNhMkM4WunONoMFusz+
JVcPyu7fFSrP/Ry0gDwxwSpqc87GXhWp3DWGTQwyvI8tD6K7Cluf05F9P456NTbn
UKre9UYjF/onz0V6nOciKdtJgaXyW2hj8oZCBwC8rdCQSe8=
-----END CERTIFICATE-----
`

func TestBasicCompile(t *testing.T) {
	pyaml := `
    zpl_format: 2
    main:
      name: foo
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
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland system
          components:
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	require.NotEmpty(t, plcy.GetPolicyMetadata())
	require.Len(t, plcy.GetConnects(), 3)
	{
		matchedP := 0

		for _, c := range plcy.GetConnects() {
			// We should find that the provider attrs fires a procedure.
			// - node is a provider
			// - visa service is a provider
			isProvider := false

			for _, attrExpr := range c.GetAttrExprs() {
				aval := plcy.GetAttrKeyIndex()[attrExpr.Key]
				if aval == "ca0.x509.cn" {
					require.NotEqual(t, defs.NoProc, c.GetProc())
					pr := plcy.GetProcs()[c.GetProc()]
					// expectProc := "000: OP_Register (/mathiasland/n0.spacelaser.net, SVCT_DEF, TCP/8182)\n001: OP_SetFlag (F_NODE)\n002: OP_SetCfg (cidr, fc00:3001:0:1::/64)\n"
					// expectProc := "000: OP_Register (/mathiasland/n0.spacelaser.net, SVCT_DEF, TCP/5002,TCP/8182)\n001: OP_SetFlag (F_NODE)\n002: OP_SetCfg (cidr, fc00:3001:0:1::/64)\n"
					// expectProc := "000: OP_Register (/zpr/mathiasland/n0.spacelaser.net, SVCT_DEF, TCP/5002,TCP/8182)\n001: OP_SetFlag (F_NODE)\n002: OP_SetFlag (F_VISASERVICE)\n003: OP_SetCfg (cidr, fc00:3001:0:1::/64)\n"
					expectProc := "000: OP_Register (/zpr/n0, SVCT_DEF, TCP/8182,TCP/8183)\n001: OP_SetFlag (F_NODE)\n002: OP_SetFlag (F_VS_DOCK)\n003: OP_SetCfg (cidr, fc00:3001:0:1::/64)\n"
					require.Equal(t, expectProc, compiler.Pseudocode(pr))
					matchedP += 1
					isProvider = true
					break
				}
				if aval == "ca0.fox" {
					require.NotEqual(t, defs.NoProc, c.GetProc())
					pr := plcy.GetProcs()[c.GetProc()]
					expectProc := "000: OP_Register (/zpr/$$zpr/visaservice, SVCT_DEF, TCP/5002,TCP/8182)\n001: OP_SetFlag (F_VISASERVICE)\n"
					matchedP++
					require.Equal(t, expectProc, compiler.Pseudocode(pr))
					matchedP += 1
					isProvider = true
					break
				}
			}
			if !isProvider {
				// Not a provider? No proc.  Is this always true?
				require.Equal(t, defs.NoProc, c.GetProc())
			}
		}
		require.GreaterOrEqual(t, matchedP, 2, "failed to locate both of the provider connections (found %d)", matchedP)
	}

	require.Len(t, plcy.GetPolicies(), 4)
	{
		// policy that allows TCP 8182 (admin), and policy that allows node access to visa service (port 5002)

		var scopes []*polio.Scope
		for _, cp := range plcy.GetPolicies() {
			scopes = append(scopes, cp.GetScope()...)
		}

		require.Len(t, scopes, 4)
		require.Equal(t, uint32(6), scopes[0].Protocol)
		require.Equal(t, uint32(6), scopes[1].Protocol)
		require.Equal(t, uint32(6), scopes[2].Protocol)
		require.Equal(t, uint32(6), scopes[3].Protocol)
		require.Contains(t, []uint32{8182, 8183, 5002}, scopes[0].GetPspec().GetSpec()[0].GetPort())
		require.Contains(t, []uint32{8182, 8183, 5002}, scopes[1].GetPspec().GetSpec()[0].GetPort())
		require.Contains(t, []uint32{8182, 8183, 5002}, scopes[2].GetPspec().GetSpec()[0].GetPort())
		require.Contains(t, []uint32{8182, 8183, 5002}, scopes[3].GetPspec().GetSpec()[0].GetPort())
	}
	require.Len(t, plcy.GetServices(), 0) // no external auth
	require.Len(t, plcy.GetCertificates(), 1)
	require.Equal(t, "ca0", plcy.GetCertificates()[0].GetName())
	require.Len(t, plcy.GetAttrKeyIndex(), 5)
	require.Contains(t, plcy.GetAttrKeyIndex(), "ca0.x509.cn")
	require.Contains(t, plcy.GetAttrKeyIndex(), "ca0.foo")
	require.Contains(t, plcy.GetAttrKeyIndex(), "ca0.fox")
	require.Contains(t, plcy.GetAttrKeyIndex(), "zpr.addr")
	require.Len(t, plcy.GetAttrValIndex(), 6)
	require.Contains(t, plcy.GetAttrValIndex(), "fee")
	require.Contains(t, plcy.GetAttrValIndex(), "foh")
	require.Contains(t, plcy.GetAttrValIndex(), "n0.internal")
	require.Contains(t, plcy.GetAttrValIndex(), "fc00:3001:abd5:d0d:847a:9fd6:586:3836")
	require.Contains(t, plcy.GetAttrValIndex(), VisaServiceAddress)
}

func TestSetDockFalse(t *testing.T) {
	// Just make sure you can set the dock attribute.
	// A compiler warning tells user that this does nothing.
	pyaml := `
    zpl_format: 2
    main:
      name: foo
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
              dock: false
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland system
          components:
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)
}

func TestFailsWithDupeSvc(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, node.n0]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3000"
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
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.f00, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services:
                - http
              policies:
                - desc: access
                  conditions:
                     - name: some users
                       attrs:
                          - [ca0.foo, eq, fee]
            foo1.spacelaser.net:
              desc: foo1 dupe
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services:
                - http
              policies:
                - desc: access dupe
                  conditions:
                    - desc: some users
                      attrs:
                        - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t02",
		Verbose:  true,
	}
	pp, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	// This is a silent failure -- the second one wins.
	// TODO: What is this testing for exactly?
	require.Equal(t, 5, len(pp.GetPolicies()))
	found := false
	for _, p := range pp.GetPolicies() {
		require.NotEqual(t, "access", p.Id)
		if p.Id == "access-dupe" {
			found = true
		}
	}
	require.True(t, found)
}

func TestFailIfMultiServiceOnOnePort(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http]
              policies:
                - desc: access
                  conditions:
                     - desc: some users
                       attrs:
                          - [ca0.foo, eq, fee]
            foo2.spacelaser.net:
              desc: foo2
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http]
              policies:
                - desc: access
                  conditions:
                    - desc: some users
                      attrs:
                        - [ca0.foo, eq, fee]
                        - [ca0.fie, ne, foe]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Regexp(t, "service on same host with overlapping scope: TCP/80", err.Error())
}

func TestPolicyServiceRestriction(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  services: [http]
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
                - desc: access for foo
                  services: [https]
                  conditions:
                    - desc: foo users
                      attrs:
                        - [ca0.foo, eq, foo]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)
}

func TestPolicyFailIfServiceNotInParent(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  services: [http]
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
                - desc: access for foo
                  services: [ssh]
                  conditions:
                    - desc: foo users
                      attrs:
                        - [ca0.foo, eq, foo]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not allowed by parent")
}

func TestFailsWithAttrExprConflict(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::1"
          provider:
            - [ca0.foo, eq, fee]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.f00, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http]
              policies:
                - desc: access
                  conditions:
                     - name: some users
                       attrs:
                          - [ca0.foo, eq, fee]
            foo1.spacelaser.net:
              desc: foo1 dupe
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http]
              policies:
                - desc: access
                  conditions:
                    - desc: some foo
                      attrs:
                        - [ca0.foo, eq, fee]
                    - desc: some other foo
                      attrs:
                        - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t02",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Regexp(t, `conflicting.*ca0.foo`, err.Error())
}

func TestMultiServiceOneHost(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.foo, eq, hello]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http]
              policies:
                - desc: access
                  conditions:
                     - desc: some users
                       attrs:
                          - [ca0.foo, eq, fee]
            foo2.spacelaser.net:
              desc: foo2
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [https]
              policies:
                - desc: access
                  conditions:
                    - desc: some users
                      attrs:
                        - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t04",
		Verbose:  true,
	}

	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	serviceProcIdx := defs.NoProc
	for _, cc := range plcy.GetConnects() {
		for _, aa := range cc.AttrExprs {
			if plcy.GetAttrKeyIndex()[aa.Key] == defs.KAttrEPID {
				if plcy.GetAttrValIndex()[aa.Val] == "fc00:3001:abd5:d0d:847a:9fd6:586:3836" {
					if serviceProcIdx == defs.NoProc {
						serviceProcIdx = cc.GetProc()
					} else {
						// Should be just one match.
						require.Fail(t, "multiple connect blocks reference zpr.addr")
					}
				}
			}
		}
	}
	require.NotEqual(t, defs.NoProc, serviceProcIdx)

	// That one proc we extracted above must register two services:
	require.Equal(t, "000: OP_Register (/zpr/mathiasland/foo1.spacelaser.net, SVCT_DEF, TCP/80)\n001: OP_Register (/zpr/mathiasland/foo2.spacelaser.net, SVCT_DEF, TCP/443)\n",
		compiler.Pseudocode(plcy.GetProcs()[serviceProcIdx]))
}

func testPolicyCompiles(t *testing.T, ppyaml string) {
	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(ppyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t05",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)
}

func TestGoodPolicy1(t *testing.T) {
	testPolicyCompiles(t, GoodPolicy1)
}

func TestGoodPolicy2(t *testing.T) {
	testPolicyCompiles(t, GoodPolicy2)
}

func TestGoodPolicy3(t *testing.T) {
	testPolicyCompiles(t, GoodPolicySpaceLaser)
}

// TODO: this is terribly hacky since the policies apply not just to the additional
// services but to all node services (eg, pmctl). Need to implement the policy.services
// tag so that a policy can work on just a subset of services.
func TestAddServicesToNode(t *testing.T) {
	pyaml := `
    zpl_format: 2

    services:
      ssh:
        tcp: 22
      prom:
        tcp: 8000

    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
          services: [ssh,prom]
          policies:
            - desc: admin can ssh
              services: [ssh]
              conditions:
                - desc: admin user
                  attrs:
                    - [ca0.foo, eq, fee]
            - desc: admin can get prom data
              services: [ssh, prom]
              conditions:
                - desc: admin user
                  attrs:
                    - [ca0.foo, eq, fee]


      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)

	require.Equal(t, 3, len(plcy.GetConnects())) // (1) the node, (2) the admin, (3) visa server adapter

	serviceProcIdx := defs.NoProc
	for _, cc := range plcy.GetConnects() {
		for _, aa := range cc.AttrExprs {
			if plcy.GetAttrKeyIndex()[aa.Key] == defs.KAttrEPID {
				if plcy.GetAttrValIndex()[aa.Val] == "fc00:3001:abd5:d0d:847a:9fd6:586:3836" {
					if serviceProcIdx == defs.NoProc {
						serviceProcIdx = cc.GetProc()
					} else {
						// Should be just one match.
						require.Fail(t, "multiple connect blocks reference zpr.addr")
					}
				}
			}
		}
	}
	require.NotEqual(t, defs.NoProc, serviceProcIdx)

	// That one proc we extracted above must register all the services
	require.Equal(t,
		"000: OP_Register (/zpr/n0, SVCT_DEF, TCP/22,TCP/8000,TCP/8182,TCP/8183)\n001: OP_SetFlag (F_NODE)\n002: OP_SetFlag (F_VS_DOCK)\n003: OP_SetCfg (cidr, fc00:3001:0:1::/64)\n",
		compiler.Pseudocode(plcy.GetProcs()[serviceProcIdx]))

}

// Ensure that we can add additional scopes to a host. In the future I think
// that the "decorator" attribute will be useful here. Until then, you must
// specified the provider and host exactly the same in each component in order
// to ensure that the services are collected on a single host.
func TestAddServicesToHost(t *testing.T) {
	pyaml := `
    zpl_format: 2

    services:
      ssh:
        tcp: 22
      http:
        tcp: 80
      https:
        tcp: 443
      prom:
        tcp: 8000

    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            hostAhttp:
              desc: host A offers HTTP
              services: [http]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              provider:
                - [ca0.x509.cn, eq, hostA]
              policies:
                - desc: allow class A
                  conditions:
                    - desc: is class A
                      attrs:
                        - [ca0.class, eq, classA]
            hostAhttps:
              desc: host A offers HTTPS
              services: [https]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              provider:
                - [ca0.x509.cn, eq, hostA]
              policies:
                - desc: allow class B
                  conditions:
                    - desc: is class B
                      attrs:
                        - [ca0.class, eq, classB]
            hostAssh:
              desc: host A offers SSH
              services: [ssh]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              provider:
                - [ca0.x509.cn, eq, hostA]
              policies:
                - desc: allow class A
                  conditions:
                    - desc: is class A
                      attrs:
                        - [ca0.class, eq, classA]
                - desc: allow class B
                  conditions:
                    - desc: is class B
                      attrs:
                        - [ca0.class, eq, classB]

    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)

	fmt.Printf(">> compiled policy %d connects, %d policies \n", len(plcy.GetConnects()), len(plcy.GetPolicies()))

	require.Equal(t, 6, len(plcy.GetConnects())) // (1) the node, (2) the admin, (3) class A, (4) class B, (5) hostA, (6) vs adapter

	serviceProcIdx := defs.NoProc
	for _, cc := range plcy.GetConnects() {
		fmt.Printf(">> processing a policy connect: PROC: %x\n", cc.GetProc())
		for _, aa := range cc.AttrExprs {
			if plcy.GetAttrKeyIndex()[aa.Key] == defs.KAttrEPID {
				if plcy.GetAttrValIndex()[aa.Val] == "fc00:3001:abd5:d0d:847a:9fd6:586:1000" {
					if serviceProcIdx == defs.NoProc {
						serviceProcIdx = cc.GetProc()
					} else {
						// Should be just one match.
						require.Fail(t, "multiple connect blocks reference hostA zpr.addr")
					}
				}
			}
		}
	}
	require.NotEqual(t, defs.NoProc, serviceProcIdx)

	// That one proc we extracted above must register all the services
	require.Equal(t,
		"000: OP_Register (/zpr/mathiasland/hostAhttp, SVCT_DEF, TCP/80)\n001: OP_Register (/zpr/mathiasland/hostAhttps, SVCT_DEF, TCP/443)\n002: OP_Register (/zpr/mathiasland/hostAssh, SVCT_DEF, TCP/22)\n",
		compiler.Pseudocode(plcy.GetProcs()[serviceProcIdx]))
}

func TestAddServicesToHostUsingSubServices(t *testing.T) {
	pyaml := `
    zpl_format: 2

    services:
      ssh:
        tcp: 22
      http:
        tcp: 80
      https:
        tcp: 443
      prom:
        tcp: 8000

    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            hostA:
              desc: host A offers HTTP
              services: [http,https,ssh]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              provider:
                - [ca0.x509.cn, eq, hostA]
              policies:
                - desc: allow class A
                  services: [http]
                  conditions:
                    - desc: is class A
                      attrs:
                        - [ca0.class, eq, classA]
                - desc: allow class B
                  services: [https]
                  conditions:
                    - desc: is class B
                      attrs:
                        - [ca0.class, eq, classB]
                - desc: allow class A
                  services: [ssh]
                  conditions:
                    - desc: is class A
                      attrs:
                        - [ca0.class, eq, classA]
                - desc: allow class B
                  services: [ssh]
                  conditions:
                    - desc: is class B
                      attrs:
                        - [ca0.class, eq, classB]

    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)

	fmt.Printf(">> compiled policy %d connects, %d policies \n", len(plcy.GetConnects()), len(plcy.GetPolicies()))

	require.Equal(t, 6, len(plcy.GetConnects())) // (1) the node, (2) the admin, (3) class A, (4) class B, (5) hostA, (6) vs adapter

	serviceProcIdx := defs.NoProc
	for _, cc := range plcy.GetConnects() {
		fmt.Printf(">> processing a policy connect: PROC: %x\n", cc.GetProc())
		for _, aa := range cc.AttrExprs {
			if plcy.GetAttrKeyIndex()[aa.Key] == defs.KAttrEPID {
				if plcy.GetAttrValIndex()[aa.Val] == "fc00:3001:abd5:d0d:847a:9fd6:586:1000" {
					if serviceProcIdx == defs.NoProc {
						serviceProcIdx = cc.GetProc()
					} else {
						// Should be just one match.
						require.Fail(t, "multiple connect blocks reference hostA zpr.addr")
					}
				}
			}
		}
	}
	require.NotEqual(t, defs.NoProc, serviceProcIdx)

	// That one proc we extracted above must register all the services
	require.Equal(t,
		"000: OP_Register (/zpr/mathiasland/hostA, SVCT_DEF, TCP/22,TCP/443,TCP/80)\n",
		compiler.Pseudocode(plcy.GetProcs()[serviceProcIdx]))
}

func TestDetectReferenceNodeInCommTree(t *testing.T) {
	pyaml := `
    zpl_format: 2

    services:
      ssh:
        tcp: 22
      http:
        tcp: 80
      t8192:
        tcp: 8192

    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            n0ssh:
              desc: add ssh to the node
              services: [ssh]
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              policies:
                - desc: admin can ssh
                  conditions:
                    - desc: admin user
                      attrs:
                        - [ca0.foo, eq, fee]
            n0pmctl:
              desc: add random service to the node
              services: [http]
              provider:
                - [ca0.x509.cn, eq, n0.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              policies:
                - desc: allow myself in
                  conditions:
                    - desc: user x
                      attrs:
                        - [ca0.foo, eq, x]

    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "duplicate provider")
}

// Should flag as error if user adds an explicit policy for PMCTL access to
// visa service node.
func TestDetectDupePMCTL(t *testing.T) {
	pyaml := `
    zpl_format: 2

    services:
      ssh:
        tcp: 22
      t8182:
        tcp: 8182

    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
          services: [t8182]
          policies:
            - desc: admin can pmctl
              conditions:
                - desc: admin user
                  attrs:
                    - [ca0.foo, eq, fee]

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "duplicate service")
}

func TestActorLimitAndGroup(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              policies:
                - desc: user access w1
                  conditions:
                    - desc: any user
                      attrs:
                        - [zpr.authority, eq, ca0]
                  constraints:
                    actor_limit: 100MB/1d @g1
            web2.service:
              desc: web02
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:2000"
              policies:
                - desc: user access w2
                  conditions:
                    - desc: any user
                      attrs:
                        - [zpr.authority, eq, ca0]
                  constraints:
                    actor_limit: 100MB/1d @g1
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	require.NotEmpty(t, plcy.GetPolicyMetadata())
	require.Len(t, plcy.GetPolicies(), 6)
	require.Len(t, plcy.GetServices(), 0) // no external auth

	for _, pcy := range plcy.GetPolicies() {
		if strings.HasPrefix(pcy.GetId(), "user-access") {
			for _, cs := range pcy.GetConstraints() {
				require.Equal(t, "g1", cs.GetGroup())
				require.NotNil(t, cs.GetCap())
				require.Equal(t, uint64(100000000), cs.GetCap().GetCapBytes())
				require.Equal(t, uint64(24*60*60), cs.GetCap().GetPeriodSeconds())
			}
		}
		if strings.HasPrefix(pcy.GetId(), "admin-access") {
			for _, cs := range pcy.GetConstraints() {
				require.Empty(t, cs.GetGroup())
				require.NotNil(t, cs.GetCap())
				require.Equal(t, uint64(10000000), cs.GetCap().GetCapBytes())
				require.Equal(t, uint64(24*60*60), cs.GetCap().GetPeriodSeconds())
			}
		}
	}
}

func TestConstraintDuration(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      t8181:
        tcp: 8181
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            foo.spacelaser.net:
              desc: f00
              services: [t8181]
              provider:
                - [ca0.x509.cn, eq, foo.internal]
              policies:
                - desc: some other service
                  conditions:
                     - desc: admin user
                       attrs:
                          - [ca0.foo, eq, fee]
                  constraints:
                    duration: 90s
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t07",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	plist := plcy.GetPolicies()
	require.Len(t, plist, 5)

	const idx = 2 // hmm...
	require.Equal(t, "some-other-service", plist[idx].Id)
	cons := plist[idx].GetConstraints()
	require.Len(t, cons, 1) // a single constraint

	dc := cons[0].GetDur()
	require.NotNil(t, dc)

	require.Equal(t, uint64(90), dc.GetSeconds())
}

func TestNoPanicOnDashInID(t *testing.T) {
	pyaml := `
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
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathias-land:
          desc: mathiasland
          components:
            n0.spacelaser.net:
              desc: node0
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Equal(t, "[communications.systems.\"mathias-land\" at /pol.yaml:31:11] not a valid system identifier: \"mathias-land\"", err.Error())
}

func TestBridgeLatencyMissing(t *testing.T) {
	pyaml := `
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
            i0:
              netaddr: "n0.spacelaser.net:5000"
        n1:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950053"
          provider:
            - [ca0.x509.cn, eq, n1.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:9999"
          interfaces:
            i0:
              netaddr: "n1.spacelaser.net:5000"

      topology:
        lans:
          lan0: [n0]
          lan1: [n1]
        bridges:
          - nodes: [n0, n1]
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        dock: n0
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	// For a period, the compiler would crash when latency was not defined in yaml.
	require.Nil(t, err)
	require.NotNil(t, plcy)
}

func TestMultiInterface(t *testing.T) {
	pyaml := `
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
            i0:
              netaddr: "n00.spacelaser.net:5000"
            i1:
              netaddr: "n01.spacelaser.net:5010"
        n1:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950053"
          provider:
            - [ca0.x509.cn, eq, n1.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:9999"
          interfaces:
            i0:
              netaddr: "n10.spacelaser.net:5000"
            i1:
              netaddr: "n11.spacelaser.net:5010"

      topology:
        lans:
          lan0: [n0.i0, n1.i0]
          lan1: [n0.i1, n1.i1]
        bridges:
          - nodes: [n0.i0, n1.i1]

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        dock: n0
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	// For a period, the compiler would crash when latency was not defined in yaml.
	require.Nil(t, err)
	require.NotNil(t, plcy)
	require.Len(t, plcy.Links, 5)
}

func TestBridgeCost(t *testing.T) {
	pyaml := `
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
            i0:
              netaddr: "n0.spacelaser.net:5000"
        n1:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950053"
          provider:
            - [ca0.x509.cn, eq, n1.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:9999"
          interfaces:
            i0:
              netaddr: "n1.spacelaser.net:5000"

      topology:
        lans:
          lan0: [n0]
          lan1: [n1]
        bridges:
          - nodes: [n0, n1]
            cost: 33
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        dock: n0
        provider:
          - [ca0.fox, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	// For a period, the compiler would crash when latency was not defined in yaml.
	require.Nil(t, err)
	require.NotNil(t, plcy)
	require.Len(t, plcy.Links, 1)
	require.Len(t, plcy.Links[0].Terms, 1)
	zlink := plcy.Links[0]
	require.Equal(t, uint32(33), zlink.Terms[0].Cost)
}

func TestDoesNotAllowDuplicateCert(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
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
              cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "duplicate key fingerprint")
}

func TestAllowRestrictsServicesInSystem(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          allow:
            services: [https]
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "disallowed service: http")
}

func TestAllowRestrictsServicesInSystemMap(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        allow:
          services: [https]
        mathiasland:
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "disallowed service: http")
}

func TestAllowRestrictsServicesInComponents(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            allow:
              services: [https]
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "disallowed service: http")
}

func TestNestedAllow(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        allow:
          services: [https, http, ssh]
        mathiasland:
          allow:
            services: [https, http]
          desc: mathiasland
          components:
            allow:
              services: [https]
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
        spencerland:
          allow:
            services: [http, ssh]
          desc: spencerland
          components:
            allow:
              services: [ssh]
            foo2.spacelaser.net:
              desc: foo2
              provider:
                - [ca0.x509.cn, eq, f2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3837"
              services: [ssh]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
}

func TestAllowRestrictsDatasourcesInConditions(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ext0:
          api: validation/1
          endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[simplev-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          allow:
            datasources: [ca0]
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ext0.foo")
}

func TestAllowPermitsZPRds(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ext0:
          api: validation/1
          endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[simplev-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          allow:
            datasources: [ca0]
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [zpr.authority, eq, ca0]
                          - [ca0.color, eq, green]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
}

func TestAllowRestrictsDatasourcesInProvider(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ext0:
          api: validation/1
          endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[simplev-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          allow:
            datasources: [ca0]
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ca0.foo, eq, fee]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ext0.")
}

func TestApplyInsertsConditions(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        apply:
          conditions:
            - desc: any user
              attrs:
                - [zpr.authority, eq, ca0]

        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:2000"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	require.NotEmpty(t, plcy.GetPolicyMetadata())

	policyByService := make(map[string][]*polio.CPolicy)
	for _, pcy := range plcy.GetPolicies() {
		plist := policyByService[pcy.ServiceId]
		plist = append(plist, pcy)
		policyByService[pcy.ServiceId] = plist
	}

	// web01 should have 1 policy with two conditions.
	require.Len(t, policyByService["/zpr/mathiasland/web01.service"], 1)

	wp := policyByService["/zpr/mathiasland/web01.service"][0]
	require.Len(t, wp.Conditions, 2)

	// web2 should have 1 policy (from apply) with one condition
	require.Len(t, policyByService["/zpr/mathiasland/web2.service"], 1)
	w2p := policyByService["/zpr/mathiasland/web2.service"][0]
	require.Len(t, w2p.Conditions, 1)
}

func TestApplyRespectsAllow(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ext0:
          api: validation/1
          endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[simplev-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        allow:
          datasources: [ext0]
        mathiasland:
          desc: mathiasland
          apply:
            conditions:
              - desc: any user
                attrs:
                  - [ca0.blah, eq, fie]
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ext0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ext0.something, eq, foo]
            web2.service:
              desc: web02
              services: [http]
              provider:
                - [ext0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:2000"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ca0.")
}

func TestNestedApply(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        apply:
          conditions:
            - desc: any user
              attrs:
                - [zpr.authority, eq, ca0]

        harryland:
          desc: harryland system
          components:
            web3.service:
              desc: web3 in harryland
              services: [http]
              provider:
                - [ca0.foo, eq, lala]

        mathiasland:
          desc: mathiasland
          apply:
            conditions:
              - desc: blue user
                attrs:
                  - [ca0.color, eq, blue]
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:2000"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	plcy, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, plcy)

	require.NotEmpty(t, plcy.GetPolicyMetadata())

	policyByService := make(map[string][]*polio.CPolicy)
	for _, pcy := range plcy.GetPolicies() {
		plist := policyByService[pcy.ServiceId]
		plist = append(plist, pcy)
		policyByService[pcy.ServiceId] = plist
	}

	// web01 should have 1 policy with 3 conditions
	require.Len(t, policyByService["/zpr/mathiasland/web01.service"], 1)

	wp := policyByService["/zpr/mathiasland/web01.service"][0]
	require.Len(t, wp.Conditions, 3)

	// web2 should have 1 policy (from apply) with 2 conditions
	require.Len(t, policyByService["/zpr/mathiasland/web2.service"], 1)
	w2p := policyByService["/zpr/mathiasland/web2.service"][0]
	require.Len(t, w2p.Conditions, 2)

	// web3 should just have 1 policy
	require.Len(t, policyByService["/zpr/harryland/web3.service"], 1)
	w3p := policyByService["/zpr/harryland/web3.service"][0]
	require.Len(t, w3p.Conditions, 1)

	require.Equal(t, "[zpr.authority, EQ, ca0]", StringifyCondition(plcy, w3p.Conditions[0]))

}

// Given a condition from THIS policy `p`, return the condition in human readable form.
// Copied from core/policy/helpers.go
func StringifyCondition(p *polio.Policy, c *polio.Condition) string {
	if len(c.AttrExprs) == 0 {
		return "[]"
	}
	var attrCount = 0
	var sb strings.Builder

	for _, exp := range c.AttrExprs {
		var kstr, valstr string
		if k, ok := lookup(p.AttrKeyIndex, int(exp.Key)); ok {
			kstr = k
		} else {
			kstr = fmt.Sprintf("<INVALID_%d>", exp.Key)
		}

		if v, ok := lookup(p.AttrValIndex, int(exp.Val)); ok {
			valstr = v
		} else {
			valstr = fmt.Sprintf("<INVALID_%d>", exp.Val)
		}
		if attrCount > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("[%v, %v, %v]", kstr, exp.Op.String(), valstr))
		attrCount++
	}

	return sb.String()
}

func lookup(inlist []string, index int) (string, bool) {
	if index < 0 || index >= len(inlist) {
		return "", false
	}
	return inlist[index], true
}

func TestAllowRestrictsDatasourcesInZprAuthority(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ext0:
          api: validation/1
          endpoint:
            provider:
              - [ca0.x509.cn, eq, simplev]
            address: "fc00:3001::1001"
            services: [auth]
            tls_domain: foo.spacelaser.net
            tls_cert:
              encoding: pem
              cert_data: $import[simplev-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          allow:
            datasources: [ca0]
          desc: mathiasland
          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ca0.x509.cn, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [zpr.authority, eq, ext0]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "'ext0' not in scope: zpr.authority")
}

const services = `
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      ssh:
        tcp: 22
      auth:
        tcp: 5001
`

func TestNestedDatasource(t *testing.T) {
	pyaml := `
    zpl_format: 2
    $import: services.yaml
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        harryland:
          desc: harryland system
          components:
            wak1.spacelaser.net:
              desc: wak1
              provider:
                - [ca0.x509.cn, eq, wak]
              services: [http]
              policies:
                - desc: my wak policy
                  conditions:
                    - desc: allow waks
                      attrs:
                        - [ca0.allow, eq, wak]

        mathiasland:
          desc: mathiasland system

          datasources:
            ext0:
              api: validation/1
              endpoint:
                provider:
                  - [ca0.x509.cn, eq, simplev]
                address: "fc00:3001::1001"
                services: [auth]
                tls_domain: foo.spacelaser.net
                tls_cert:
                  encoding: pem
                  cert_data: $import[simplev-cert.pem]

          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.permit, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.color, eq, green]
                          - [ca0.vibe, has, mellow]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))
	fst.AddFile("/services.yaml", []byte(services))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
}

// Datasource attempts to use a forbidden datasource in its definition.
func TestNestedDatasourceUnderAllow(t *testing.T) {
	pyaml := `
    zpl_format: 2
    $import: services.yaml
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ca1:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca1-cert.pem]

      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        harryland:
          desc: harryland system
          components:
            wak1.spacelaser.net:
              desc: wak1
              provider:
                - [ca0.x509.cn, eq, wak]
              services: [http]
              policies:
                - desc: my wak policy
                  conditions:
                    - desc: allow waks
                      attrs:
                        - [ca0.allow, eq, wak]

        mathiasland:
          desc: mathiasland system
          allow:
            datasources: [ca0]

          datasources:
            ext0:
              api: validation/1
              endpoint:
                provider:
                  - [ca1.x509.cn, eq, simplev]
                address: "fc00:3001::1001"
                services: [auth]
                tls_domain: foo.spacelaser.net
                tls_cert:
                  encoding: pem
                  cert_data: $import[simplev-cert.pem]

          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.permit, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.color, eq, green]
                          - [ca0.vibe, has, mellow]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/ca1-cert.pem", []byte(ca1cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))
	fst.AddFile("/services.yaml", []byte(services))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ca1.")
}

// Datasource should not be accessible from sibling branch.
func TestNestedDatasourceIsHierarchical(t *testing.T) {
	pyaml := `
    zpl_format: 2
    $import: services.yaml
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ca1:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca1-cert.pem]

      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        harryland:
          desc: harryland system
          components:
            wak1.spacelaser.net:
              desc: wak1
              provider:
                - [ca0.x509.cn, eq, wak]
              services: [http]
              policies:
                - desc: my wak policy
                  conditions:
                    - desc: allow waks
                      attrs:
                        - [ext0.allow, eq, wak]

        mathiasland:
          desc: mathiasland system

          datasources:
            ext0:
              api: validation/1
              endpoint:
                provider:
                  - [ca1.x509.cn, eq, simplev]
                address: "fc00:3001::1001"
                services: [auth]
                tls_domain: foo.spacelaser.net
                tls_cert:
                  encoding: pem
                  cert_data: $import[simplev-cert.pem]

          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.permit, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.color, eq, green]
                          - [ca0.vibe, has, mellow]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/ca1-cert.pem", []byte(ca1cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))
	fst.AddFile("/services.yaml", []byte(services))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ext0.")
}

// Positive check that you can use a nested datasource in an allow clause.
func TestNestedDatasourceWorksInAllow(t *testing.T) {
	pyaml := `
    zpl_format: 2
    $import: services.yaml
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ca1:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca1-cert.pem]

      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        harryland:
          desc: harryland system
          components:
            wak1.spacelaser.net:
              desc: wak1
              provider:
                - [ca0.x509.cn, eq, wak]
              services: [http]
              policies:
                - desc: my wak policy
                  conditions:
                    - desc: allow waks
                      attrs:
                        - [ca1.allow, eq, wak]

        mathiasland:
          desc: mathiasland system

          datasources:
            ext0:
              api: validation/1
              endpoint:
                provider:
                  - [ca1.x509.cn, eq, simplev]
                address: "fc00:3001::1001"
                services: [auth]
                tls_domain: foo.spacelaser.net
                tls_cert:
                  encoding: pem
                  cert_data: $import[simplev-cert.pem]

          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.permit, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.color, eq, green]
                          - [ca0.vibe, has, mellow]

          systems:
            subsubland:
              desc: subsubland is a system inside mathiasland
              allow:
                datasources: [ext0]
              components:
                smack.spacelaser.net:
                  desc: smack
                  provider:
                    - [ext0.permit, eq, f2.internal]
                  services: [http]
                  policies:
                    - desc: access for smack
                      conditions:
                        - desc: smack users
                          attrs:
                            - [ext0.blah, eq, blow]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/ca1-cert.pem", []byte(ca1cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))
	fst.AddFile("/services.yaml", []byte(services))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)

}

// Use a nested DS in an allow clause and then violate it.
func TestNestedDatasourceEnforcedInAllow(t *testing.T) {
	pyaml := `
    zpl_format: 2
    $import: services.yaml
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001::88"
          provider:
            - [ca0.fee, eq, foo]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
        ca1:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca1-cert.pem]

      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        harryland:
          desc: harryland system
          components:
            wak1.spacelaser.net:
              desc: wak1
              provider:
                - [ca0.x509.cn, eq, wak]
              services: [http]
              policies:
                - desc: my wak policy
                  conditions:
                    - desc: allow waks
                      attrs:
                        - [ca1.allow, eq, wak]

        mathiasland:
          desc: mathiasland system

          datasources:
            ext0:
              api: validation/1
              endpoint:
                provider:
                  - [ca1.x509.cn, eq, simplev]
                address: "fc00:3001::1001"
                services: [auth]
                tls_domain: foo.spacelaser.net
                tls_cert:
                  encoding: pem
                  cert_data: $import[simplev-cert.pem]

          components:
            foo1.spacelaser.net:
              desc: foo1
              provider:
                - [ext0.permit, eq, f1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
              services: [http, https]
              policies:
                - desc: access for fee
                  conditions:
                     - desc: fee users
                       attrs:
                          - [ext0.color, eq, green]
                          - [ca0.vibe, has, mellow]

          systems:
            subsubland:
              desc: subsubland is a system inside mathiasland
              allow:
                datasources: [ext0]
              components:
                smack.spacelaser.net:
                  desc: smack
                  provider:
                    - [ext0.permit, eq, f2.internal]
                  services: [http]
                  policies:
                    - desc: access for smack
                      conditions:
                        - desc: smack users
                          attrs:
                            - [ca1.blah, eq, blow]
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/ca1-cert.pem", []byte(ca1cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))
	fst.AddFile("/services.yaml", []byte(services))

	opts := &compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not in scope: ca1.")
}

func TestSingleTenantEnforced(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              single_tenant: true
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [https]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "single-tenant")
}

func TestSingleTenantEnforcedOnSet(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              single_tenant: true
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [https]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address_set:
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1001"
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1002"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "single-tenant")
}

func TestSingleTenantOKWithNonOverlap(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              single_tenant: true
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [https]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address_set:
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1001"
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1002"
                - "fc00:3001:abd5:d0d:847a:9fd6:586:1003"
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
}

func TestFailsWithOnlyDecorator(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              decorator: true
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [https]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1001"
              decorator: true
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "only decorator type services")
}

func TestOKWithDecorator(t *testing.T) {
	pyaml := `
    zpl_format: 2
    services:
      http:
        tcp: 80
      https:
        tcp: 443
      auth:
        tcp: 5001
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:3836"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          interfaces:
            i0:
              netaddr: "n0.spacelaser.net:5000"

      topology:
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
          components:
            web01.service:
              desc: web01
              services: [http]
              provider:
                - [ca0.x509.cn, eq, web1.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1000"
              policies:
                - desc: foo access
                  conditions:
                    - attrs:
                        - [ca0.something, eq, foo]
            web2.service:
              desc: web02
              services: [https]
              provider:
                - [ca0.x509.cn, eq, web2.internal]
              address: "fc00:3001:abd5:d0d:847a:9fd6:586:1001"
              decorator: true
    `

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))
	fst.AddFile("/simplev-cert.pem", []byte(simplevCert))

	opts := &compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
}

func TestNodeKeysMustBeUnique(t *testing.T) {
	pyaml := `
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
            i0:
              netaddr: "n0.spacelaser.net:5000"
        n1:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n1.internal]
          address: "fc00:3001:abd5:d0d:847a:9fd6:586:9999"
          interfaces:
            i0:
              netaddr: "n1.spacelaser.net:5000"

      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        dock: n0
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.NotNil(t, err)
	require.ErrorContains(t, err, "duplicate node key value")
}

func TestWillNotPermitNonDefaultAPISpecForInternalDS(t *testing.T) {
	pyaml := `
    zpl_format: 2
    main:
      name: foo
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
          api: validation/33
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland system
          components:
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	_, err := compiler.Compile("/pol.yaml", fst, opts)
	require.ErrorContains(t, err, "validation/1")
}

func TestCompilesICMPv4(t *testing.T) {
	pyaml := `
    zpl_format: 2
    main:
      name: foo
    services:
      http:
        tcp: 80
      ping:
        icmp:
          type: request-response
          type_codes: 8, 0
    zpr:
      nodes:
        n0:
          key: "13024a188fddbc76db8ee98eeef91ad81a80846e99f6f9b988184a2173950052"
          provider:
            - [ca0.x509.cn, eq, n0.internal]
          address: "10.0.0.7"
          interfaces:
            n0i0:
              netaddr: "n0.spacelaser.net:5000"
          services:
            - ping
          policies:
            - desc: allow ping
              conditions:
                - desc: match on authority
                  attrs:
                    - [zpr.authority, eq, ca0]
      datasources:
        ca0:
          api: validation/1
          authority:
            encoding: pem
            cert_data: $import[ca0-cert.pem]
      visaservice:
        provider:
          - [ca0.fox, eq, foh]
        admin_attrs:
          - [ca0.foo, eq, fee]

    communications:
      systems:
        mathiasland:
          desc: mathiasland system
          components:
`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/pol.yaml", []byte(pyaml))
	fst.AddFile("/ca0-cert.pem", []byte(ca0cert))

	opts := &compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	p, err := compiler.Compile("/pol.yaml", fst, opts)
	require.Nil(t, err)
	require.NotNil(t, p)
}

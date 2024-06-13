package vservice_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/fs"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice"
)

/*
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
*/

const policySimple1 = `
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

communications:
  systems:
    mathiasland:
      desc: mathiasland
`

const policyThreeNodes = `
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
    n1:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a00"
      provider:
        - [ca0.x509.cn, eq, n1.internal]
      address: "fc00:3001:1::12"
      interfaces:
        i0:
          netaddr: "n1.spacelaser.net:5000"
    n2:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a01"
      provider:
        - [ca0.x509.cn, eq, n2.internal]
      address: "fc00:3001:1::13"
      interfaces:
        i0:
          netaddr: "n2.spacelaser.net:5000"
           
  visaservice:
    dock: n0
    provider:
      - [ca0.foo, eq, fox]
    admin_attrs:
      - [ca0.foo, eq, fee]
  topology:
    lans:
      lan0: [n0, n1]
      lan1: [n2]
    bridges:
      - nodes: [n0, n2]
        const: 1

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

const policyHTTP = `
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

communications:
  systems:
    mathiasland:
      desc: mathiasland
      components:
        rfc.svc:
          desc: ye olde rfc service
          services: [http]
          provider:
            - [ca0.id, eq, 007]
          address: "fc00:3001:0200::100"
          policies:
            - desc: all access
              conditions:
                - desc: anyone on our authority
                  attrs:
                    - [zpr.authority, eq, ca0]
`

// Just like HTTP but here we ensure that node constraint is only on the web access policy.
// Because compiler adds additional services to the node.
// TODO: Compiler should ensure that user puts explicit services block in the
//
//	node policies when present.
const policyHTTPALT = `
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
           services: [http]
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

communications:
  systems:
    mathiasland:
      desc: mathiasland
      components:
        rfc.svc:
          desc: ye olde rfc service
          services: [http]
          provider:
            - [ca0.id, eq, 007]
          address: "fc00:3001:0200::100"
          policies:
            - desc: all access
              conditions:
                - desc: anyone on our authority
                  attrs:
                    - [zpr.authority, eq, ca0]
`

const policyHTTPnHTTPS = `
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

communications:
  systems:
    mathiasland:
      desc: mathiasland
      components:
        rfc.svc:
          desc: ye olde rfc service
          services: [http, https]
          provider:
            - [ca0.id, eq, 007]
          address: "fc00:3001:0200::100"
          policies:
            - desc: all access
              conditions:
                - desc: anyone on our authority
                  attrs:
                    - [zpr.authority, eq, ca0]
`

const policyHTTPnHTTPSALT = `
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
           services: [http]
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

communications:
  systems:
    mathiasland:
      desc: mathiasland
      components:
        rfc.svc:
          desc: ye olde rfc service
          services: [http, https]
          provider:
            - [ca0.id, eq, 007]
          address: "fc00:3001:0200::100"
          policies:
            - desc: all access
              conditions:
                - desc: anyone on our authority
                  attrs:
                    - [zpr.authority, eq, ca0]
`

func compilePolicy(t *testing.T, pyaml string) *policy.Policy {
	llog := logr.NewTestLogger()

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
	return policy.NewPolicyFromPol(plcy, llog)
}

func TestSamePolicySameConfig(t *testing.T) {
	p1 := compilePolicy(t, policySimple1)
	p2 := compilePolicy(t, policySimple1)
	id, err := vservice.ComputeConfiguration(logr.NewTestLogger(), p1, 99, p2)
	require.Nil(t, err)
	require.Equal(t, uint64(99), id)
}

func TestDifferentDSDifferentConfig(t *testing.T) {
	p1 := compilePolicy(t, policySimple1)
	altered := strings.ReplaceAll(
		strings.ReplaceAll(policySimple1, "ca0.", "ca1."),
		"ca0:", "ca1:")
	p2 := compilePolicy(t, altered)
	id, err := vservice.ComputeConfiguration(logr.NewTestLogger(), p1, 99, p2)
	require.Nil(t, err)
	require.NotEqual(t, uint64(99), id)
}

func TestUpdatesConfigFromEmptyPolicy(t *testing.T) {
	p1 := compilePolicy(t, policySimple1)
	id, err := vservice.ComputeConfiguration(logr.NewTestLogger(), nil, policy.InitialConfiguration, p1)
	require.Nil(t, err)
	require.Greater(t, id, uint64(1))
}

func TestConfigIDIncreasing(t *testing.T) {
	p1 := compilePolicy(t, policySimple1)
	id, err := vservice.ComputeConfiguration(logr.NewTestLogger(), nil, policy.InitialConfiguration, p1)
	require.Nil(t, err)
	require.Greater(t, id, uint64(1))

	altered := strings.ReplaceAll(
		strings.ReplaceAll(policySimple1, "ca0.", "ca1."),
		"ca0:", "ca1:")
	p2 := compilePolicy(t, altered)

	nextID, err := vservice.ComputeConfiguration(logr.NewTestLogger(), p1, id, p2)
	require.Nil(t, err)
	require.NotEqual(t, nextID, id)
	require.Greater(t, nextID, id)
}

func TestDifferentTopologyDifferentConfig(t *testing.T) {
	log := logr.NewTestLogger()
	p1 := compilePolicy(t, policySimple1)

	id, err := vservice.ComputeConfiguration(log, nil, policy.InitialConfiguration, p1)
	require.Nil(t, err)

	p2 := compilePolicy(t, policyThreeNodes)
	nextID, err := vservice.ComputeConfiguration(log, p1, id, p2)
	require.Nil(t, err)
	require.Greater(t, nextID, id)

	// Now alter the bridge
	policyThreeNodesAltered := strings.ReplaceAll(policyThreeNodes, "nodes: [n0, n2]", "nodes: [n1, n2]")
	p3 := compilePolicy(t, policyThreeNodesAltered)
	nextNextID, err := vservice.ComputeConfiguration(log, p2, nextID, p3)
	require.Nil(t, err)
	require.Greater(t, nextNextID, nextID)
}

func TestDifferentServiceRemovedDifferentConfig(t *testing.T) {
	log := logr.NewTestLogger()
	p1 := compilePolicy(t, policyHTTPnHTTPS)

	id, err := vservice.ComputeConfiguration(log, nil, policy.InitialConfiguration, p1)
	require.Nil(t, err)

	p2 := compilePolicy(t, policyHTTP) // removes HTTPS
	nextID, err := vservice.ComputeConfiguration(log, p1, id, p2)
	require.Nil(t, err)
	require.Greater(t, nextID, id)
}

func TestDifferentServiceAddedSameConfig(t *testing.T) {
	log := logr.NewTestLogger()
	for i := 0; i < 100; i++ {
		p1 := compilePolicy(t, policyHTTP)
		initialID, err := vservice.ComputeConfiguration(log, nil, policy.InitialConfiguration, p1)
		require.Nil(t, err)

		p2 := compilePolicy(t, policyHTTPnHTTPS) // keeps HTTP and adds HTTPS

		nextID, err := vservice.ComputeConfiguration(log, p1, initialID, p2)
		require.Nil(t, err)
		require.Equal(t, nextID, initialID, "unexpected config change on iter %d", i) // no change
	}
}

func TestDifferentServiceAddedSameConfigRestrictNodeWeb(t *testing.T) {
	log := logr.NewTestLogger()
	for i := 0; i < 100; i++ {
		p1 := compilePolicy(t, policyHTTPALT)

		initialID, err := vservice.ComputeConfiguration(log, nil, policy.InitialConfiguration, p1)
		require.Nil(t, err)

		p2 := compilePolicy(t, policyHTTPnHTTPSALT) // keeps HTTP and adds HTTPS

		nextID, err := vservice.ComputeConfiguration(log, p1, initialID, p2)
		require.Nil(t, err)
		require.Equal(t, nextID, initialID, "unexpected config change on iter %d", i) // no change
	}
}

package policy_test

import (
	"time"

	"zpr.org/vs/pkg/actor"
)

func mkClaim(val string, ttl time.Duration) *actor.ClaimV {
	return &actor.ClaimV{
		V:   val,
		Exp: time.Now().Add(ttl),
	}
}

func mkClaims(key, val string, ttl time.Duration) map[string]*actor.ClaimV {
	m := make(map[string]*actor.ClaimV)
	m[key] = mkClaim(val, ttl)
	return m
}

/* DISABLED UNTIL WE SORT OUT COMPILER

const mtpreamble = `
zpl_format: 2
main:
  policy_version: 1
  policy_date: "2020-10-22T12:23:00Z"

services:
  http:
    tcp: 80
  ping:
    icmp:
      type: request-response
      type_codes: 128, 129
`

const network = `
zpr:
  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3
  visaservice:
    provider:
      - [intern.foo, fox]
    admin_attrs:
      - [intern.foo, fee]
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [intern.cn, eq, nodus]
      address: "fc00:3001::88"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
  addresses:
    node_net: "fc00:3002::0/32"
    zpr_net: "fc00:3001::0/32"
  datasources:
    intern:
      api: validation/1
      authority:
        encoding: pem
        cert_data: |
                    -----BEGIN CERTIFICATE-----
                    MIIDlDCCAnwCCQC8eSseeO7eyzANBgkqhkiG9w0BAQsFADCBizELMAkGA1UEBhMC
                    VVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3ZpbGxlMQswCQYDVQQKDAJB
                    STEQMA4GA1UECwwHc3VyZW5ldDEdMBsGA1UEAwwUYXV0aDAuc3BhY2VsYXNlci5u
                    ZXQxHDAaBgkqhkiG9w0BCQEWDW1hdGhpYXNAYWkuY28wHhcNMTkwMzE5MTUxNTE3
                    WhcNMjAwMzE4MTUxNTE3WjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMw
                    EQYDVQQHDApMb3Vpc3ZpbGxlMQswCQYDVQQKDAJBSTEQMA4GA1UECwwHc3VyZW5l
                    dDEdMBsGA1UEAwwUYXV0aDAuc3BhY2VsYXNlci5uZXQxHDAaBgkqhkiG9w0BCQEW
                    DW1hdGhpYXNAYWkuY28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDh
                    FIpG5LpTIrhaM2vsccVRJjLbOTZvXf2kBlNDX+HeK59KLUoS/TSV7AR4Yj56uOO6
                    6iUl17r6ukxlPhqyH0+26DfKCuAsAO72nFSLEAgEqoJBxhuKZB25Qr7ZSnVu6S4J
                    sOCmW4z87jZmAZ6kSRw+ReVrqzDj67mihHCasOfYsGnZAp+1/5nqBvW+7CQlxJt4
                    im4IKDb21kIRtn4EjYzf/ecysD3Hqcb8qY6Cq7AWibajhZWmkQVkWfOc0hfixUck
                    2Szjm+uzZb1ZwCCZFIXEnUvQ5lOiswOkuy2+t/mEiWvhLtRrXms/dhKUtqtyhtGO
                    dkPuT2zDmOtB92gb2ttxAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMGvqGBGTVUd
                    6tpyhcm6J9o1P7pnOjc4HlDpOebqPMnwkuWmOOODshbFD/biDDNtpPt9DikAiSqZ
                    iVZ/RC6r42dVH0G4tiiQJDPLsLJ0pj/cdJnmmYXwUUqE4IXxsqbKMkhToZlp9Yw1
                    N+wBxdue8Nix5LhI7YYfut1JlMqtho6hxX712uMlZqUJUFsPUPErxKQIcuwuDJmP
                    RQiwkwIEZOEvrIQjkFUy+wOxsJI9cqtpVE1hSSc1dwAL0tjLqO5LtQhBMFORXUuK
                    R+E8nfJH0YhY9AIiRjJM6Gujxa9lMofSlHK0LtS7jaDnbFVsKa4fK8iIAlqGDSnc
                    roROWU/mSb0=
                    -----END CERTIFICATE-----
`

// IPv4 version
const mtpreambleIP4 = `
zpl_format: 2
main:
  policy_version: 1
  policy_date: "2020-10-22T12:23:00Z"

services:
  http:
    tcp: 80
  ping:
    icmp:
      type: request-response
      type_codes: 8, 0
`

// IPv4 version
const networkIP4 = `
zpr:
  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3
  visaservice:
    provider:
      - [intern.foo, fox]
    admin_attrs:
      - [intern.foo, fee]
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [intern.cn, eq, nodus]
      address: "10.0.0.88"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
  addresses:
    node_net: "10.0.0.0/24"
    zpr_net: "10.1.0.0/24"
  datasources:
    intern:
      api: validation/1
      authority:
        encoding: pem
        cert_data: |
                    -----BEGIN CERTIFICATE-----
                    MIIDlDCCAnwCCQC8eSseeO7eyzANBgkqhkiG9w0BAQsFADCBizELMAkGA1UEBhMC
                    VVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3ZpbGxlMQswCQYDVQQKDAJB
                    STEQMA4GA1UECwwHc3VyZW5ldDEdMBsGA1UEAwwUYXV0aDAuc3BhY2VsYXNlci5u
                    ZXQxHDAaBgkqhkiG9w0BCQEWDW1hdGhpYXNAYWkuY28wHhcNMTkwMzE5MTUxNTE3
                    WhcNMjAwMzE4MTUxNTE3WjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMw
                    EQYDVQQHDApMb3Vpc3ZpbGxlMQswCQYDVQQKDAJBSTEQMA4GA1UECwwHc3VyZW5l
                    dDEdMBsGA1UEAwwUYXV0aDAuc3BhY2VsYXNlci5uZXQxHDAaBgkqhkiG9w0BCQEW
                    DW1hdGhpYXNAYWkuY28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDh
                    FIpG5LpTIrhaM2vsccVRJjLbOTZvXf2kBlNDX+HeK59KLUoS/TSV7AR4Yj56uOO6
                    6iUl17r6ukxlPhqyH0+26DfKCuAsAO72nFSLEAgEqoJBxhuKZB25Qr7ZSnVu6S4J
                    sOCmW4z87jZmAZ6kSRw+ReVrqzDj67mihHCasOfYsGnZAp+1/5nqBvW+7CQlxJt4
                    im4IKDb21kIRtn4EjYzf/ecysD3Hqcb8qY6Cq7AWibajhZWmkQVkWfOc0hfixUck
                    2Szjm+uzZb1ZwCCZFIXEnUvQ5lOiswOkuy2+t/mEiWvhLtRrXms/dhKUtqtyhtGO
                    dkPuT2zDmOtB92gb2ttxAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMGvqGBGTVUd
                    6tpyhcm6J9o1P7pnOjc4HlDpOebqPMnwkuWmOOODshbFD/biDDNtpPt9DikAiSqZ
                    iVZ/RC6r42dVH0G4tiiQJDPLsLJ0pj/cdJnmmYXwUUqE4IXxsqbKMkhToZlp9Yw1
                    N+wBxdue8Nix5LhI7YYfut1JlMqtho6hxX712uMlZqUJUFsPUPErxKQIcuwuDJmP
                    RQiwkwIEZOEvrIQjkFUy+wOxsJI9cqtpVE1hSSc1dwAL0tjLqO5LtQhBMFORXUuK
                    R+E8nfJH0YhY9AIiRjJM6Gujxa9lMofSlHK0LtS7jaDnbFVsKa4fK8iIAlqGDSnc
                    roROWU/mSb0=
                    -----END CERTIFICATE-----
`

// MatchTrafficActors helper to call matcher.MatchTraffic
func MatchTrafficActors(m *policy.Matcher, td *snip.Traffic, src, dst *actor.Actor) ([]*policy.MatchedPolicy, error) {
	mtSrc, mtDst := &policy.ActorInfo{src.GetAuthedClaims(), src.GetProvides()}, &policy.ActorInfo{dst.GetAuthedClaims(), dst.GetProvides()}
	return m.MatchTraffic(td, mtSrc, mtDst)
}


func TestSimpleTCPClientToServer(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, fc00:3001::683c:c1ec:6785:af0]  # TODO op=eq assumed for now
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		matches, err := MatchTrafficActors(m, td, client, server)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		match := matches[0]
		require.True(t, match.FWD)
		require.Equal(t, "access", match.CPol.Id)
		require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
	}

	// Sanity check:
	{
		wrongServer := actor.NewActorFromUnsubstantiatedClaims(nil)
		wrongServer.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
		wrongServer.SetProvides([]string{"/zpr/testnet/database"})

		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"), // Note we don't care about address
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		_, err := MatchTrafficActors(m, td, client, wrongServer)
		require.NotNil(t, err)
	}
}

func TestSimpleTCPServerResponse(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t02",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			SrcPort: 80,
			DstAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			DstPort: 23576,
			Flags:   uint32(0x10), // ACK
		}

		matches, err := MatchTrafficActors(m, td, server, client)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		match := matches[0]
		require.False(t, match.FWD) // a response so should be reverse match
		require.Equal(t, "access", match.CPol.Id)
		require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
	}
	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			SrcPort: 80,
			DstAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			DstPort: 51192,
			Flags:   uint32(0x10), // ACK
		}

		matches, err := MatchTrafficActors(m, td, server, client)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		match := matches[0]
		require.False(t, match.FWD) // a response so should be reverse match
		require.Equal(t, "access", match.CPol.Id)
		require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
	}
}

func TestSimpleTCPServerCannotSYNClient(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t03",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	td := &snip.Traffic{
		Proto:   snip.ProtocolTCP,
		SrcAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		SrcPort: 80,
		DstAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		DstPort: 23576,
		Flags:   uint32(0x02), // SYN
	}

	_, err = MatchTrafficActors(m, td, server, client)
	require.NotNil(t, err)
}

func TestICMPEchoRequest(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http, ping]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t04",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	td := &snip.Traffic{
		Proto:    snip.ProtocolICMP6,
		SrcAddr:  netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		DstAddr:  netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		ICMPType: 0x80,
		ICMPCode: 0,
	}

	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	match := matches[0]
	require.True(t, match.FWD)
	require.Equal(t, "access", match.CPol.Id)
	require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
}

func TestICMPEchoResponse(t *testing.T) { // TODO: Waiting to figure out address
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http, ping]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t05",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	td := &snip.Traffic{
		Proto:    snip.ProtocolICMP6,
		SrcAddr:  netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		DstAddr:  netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		ICMPType: 0x81,
		ICMPCode: 0,
	}

	matches, err := MatchTrafficActors(m, td, server, client)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	match := matches[0]
	require.False(t, match.FWD)
	require.Equal(t, "access", match.CPol.Id)
	require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
}

func TestTCPServerConnect(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t06",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)

	state, err := policy.NewConnectState(server, nil, netip.Addr{}, logr.NewTestLogger())
	require.Nil(t, err)
	matchingAttrs, err := m.MatchConnect(state)
	require.Nil(t, err)
	require.Equal(t, []string{"/zpr/testnet/webserver"}, server.GetProvides())
	require.Equal(t, []string{"zpr.addr"}, matchingAttrs)
}

func TestTCPServerConnectNotPermitted(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t07",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.whack", "yes", time.Hour), time.Time{}, nil, nil, 1)

	state, err := policy.NewConnectState(client, nil, netip.Addr{}, logr.NewTestLogger())
	require.Nil(t, err)
	_, err = m.MatchConnect(state)
	require.NotNil(t, err)
}

func TestTCPClientToServerWithEPIDAttr(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [zpr.addr, eq, fc00:3001::fa57:abcf:9895:6469]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t08",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	{
		ac := mkClaims("intern.foo", "fee", time.Hour)
		ac["zpr.addr"] = mkClaim("fc00:3001::fa57:abcf:9895:6469", time.Hour)
		client.SetAuthenticated(ac, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	}

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::fa57:abcf:9895:6469"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		matches, err := MatchTrafficActors(m, td, client, server)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		match := matches[0]
		require.True(t, match.FWD)
		require.Equal(t, "access", match.CPol.Id)
		require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
	}
}

func TestConstraintCombine(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access FEE
              conditions:
                - desc: fee access
                  attrs:
                    - [intern.foo, eq, fee]
              constraints:
                bandwidth: 1Mbps
            - desc: access FOO
              conditions:
                - desc: foo access
                  attrs:
                    - [intern.fee, eq, foo]
              constraints:
                bandwidth: 10Mbps
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t09",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := map[string]*actor.ClaimV{
		"intern.foo": mkClaim("fee", time.Hour),
		"intern.fee": mkClaim("foo", time.Hour),
	}
	client.SetAuthenticated(claims, time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		matches, err := MatchTrafficActors(m, td, client, server)
		require.Nil(t, err)
		require.Len(t, matches, 2)
		require.True(t, matches[0].FWD)
		require.True(t, matches[1].FWD)
		require.Contains(t, []string{matches[0].CPol.Id, matches[1].CPol.Id}, "access-FEE")
		require.Contains(t, []string{matches[0].CPol.Id, matches[1].CPol.Id}, "access-FOO")
		require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)
		require.Equal(t, "/zpr/testnet/webserver", matches[1].CPol.ServiceId)
	}

}

func TestMixedCaseAttrKey(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access FEE
              conditions:
                - desc: fee access
                  attrs:
                    - [intern.Foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t10",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := mkClaims("intern.Foo", "fee", time.Hour)
	client.SetAuthenticated(claims, time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		matches, err := MatchTrafficActors(m, td, client, server)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		require.True(t, matches[0].FWD)
		require.Equal(t, matches[0].CPol.Id, "access-FEE")
		require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)
	}
}

func TestMixedCaseAttrVal(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: access FEE
              conditions:
                - desc: fee access
                  attrs:
                    - [intern.foo, eq, fEE]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t11",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := mkClaims("intern.foo", "fEE", time.Hour)
	client.SetAuthenticated(claims, time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	{
		td := &snip.Traffic{
			Proto:   snip.ProtocolTCP,
			SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
			SrcPort: 23576,
			DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
			DstPort: 80,
			Flags:   uint32(0x02), // SYN
		}

		matches, err := MatchTrafficActors(m, td, client, server)
		require.Nil(t, err)
		require.Len(t, matches, 1)
		require.True(t, matches[0].FWD)
		require.Equal(t, matches[0].CPol.Id, "access-FEE")
		require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)
	}
}

func TestAttrEq(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: eq test
              conditions:
                - desc: foo == fee
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t12",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	td := &snip.Traffic{
		Proto:   snip.ProtocolTCP,
		SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		SrcPort: 23576,
		DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		DstPort: 80,
		Flags:   uint32(0x02), // SYN
	}

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	client := actor.NewActorFromUnsubstantiatedClaims(nil)

	claims0 := mkClaims("intern.foo", "fee", time.Hour)
	client.SetAuthenticated(claims0, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	require.True(t, matches[0].FWD)
	require.Equal(t, matches[0].CPol.Id, "eq-test")
	require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)

	claims1 := mkClaims("intern.foo", "notfee", time.Hour)
	client.SetAuthenticated(claims1, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	_, err = MatchTrafficActors(m, td, client, server)
	require.NotNil(t, err)
}

func TestAttrNe(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: ne test
              conditions:
                - desc: foo != fee
                  attrs:
                    - [intern.foo, ne, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t13",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	td := &snip.Traffic{
		Proto:   snip.ProtocolTCP,
		SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		SrcPort: 23576,
		DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		DstPort: 80,
		Flags:   uint32(0x02), // SYN
	}

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	client := actor.NewActorFromUnsubstantiatedClaims(nil)

	claims0 := mkClaims("intern.foo", "notfee", time.Hour)
	client.SetAuthenticated(claims0, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	require.True(t, matches[0].FWD)
	require.Equal(t, matches[0].CPol.Id, "ne-test")
	require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)

	claims1 := mkClaims("intern.foo", "fee", time.Hour)
	client.SetAuthenticated(claims1, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	_, err = MatchTrafficActors(m, td, client, server)
	require.NotNil(t, err)
}

func TestAttrHas(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: has test
              conditions:
                - desc: foo has fee
                  attrs:
                    - [intern.foo, has, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t14",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	td := &snip.Traffic{
		Proto:   snip.ProtocolTCP,
		SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		SrcPort: 23576,
		DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		DstPort: 80,
		Flags:   uint32(0x02), // SYN
	}

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	client := actor.NewActorFromUnsubstantiatedClaims(nil)

	claims0 := mkClaims("intern.foo", "there,is,a,fee,here", time.Hour)
	client.SetAuthenticated(claims0, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	require.True(t, matches[0].FWD)
	require.Equal(t, matches[0].CPol.Id, "has-test")
	require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)

	claims1 := mkClaims("intern.foo", "there,is,a,nonfee,here", time.Hour)
	client.SetAuthenticated(claims1, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	_, err = MatchTrafficActors(m, td, client, server)
	require.NotNil(t, err)
}

func TestAttrExcludes(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.addr, eq, fc00:3001::683c:c1ec:6785:af0]
          address: "fc00:3001::683c:c1ec:6785:af0"
          policies:
            - desc: excludes test
              conditions:
                - desc: foo excludes fee
                  attrs:
                    - [intern.foo, excludes, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t15",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	td := &snip.Traffic{
		Proto:   snip.ProtocolTCP,
		SrcAddr: netip.MustParseAddr("fc00:3001::6dcd:97a3:2cbf:1f5a"),
		SrcPort: 23576,
		DstAddr: netip.MustParseAddr("fc00:3001::683c:c1ec:6785:af0"),
		DstPort: 80,
		Flags:   uint32(0x02), // SYN
	}

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "fc00:3001::683c:c1ec:6785:af0", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	client := actor.NewActorFromUnsubstantiatedClaims(nil)

	claims0 := mkClaims("intern.foo", "there,is,a,nonfee,here", time.Hour)
	client.SetAuthenticated(claims0, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	require.True(t, matches[0].FWD)
	require.Equal(t, matches[0].CPol.Id, "excludes-test")
	require.Equal(t, "/zpr/testnet/webserver", matches[0].CPol.ServiceId)

	claims1 := mkClaims("intern.foo", "there,is,a,fee,here", time.Hour)
	client.SetAuthenticated(claims1, time.Time{}, []string{"intern"}, []string{"token"}, 1)
	_, err = MatchTrafficActors(m, td, client, server)
	require.NotNil(t, err)
}

func TestWithNilPolicy(t *testing.T) {
	m, err := policy.NewMatcher(nil, 1, logr.NewTestLogger())
	require.Nil(t, err)
	require.NotNil(t, m)
}

func TestICMP4EchoRequest(t *testing.T) {
	pyml := mtpreambleIP4 + networkIP4 + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http, ping]
          provider:
            - [zpr.addr, eq, 10.1.0.8]
          address: "10.1.0.8"
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t04",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	client.SetAuthenticated(mkClaims("intern.foo", "fee", time.Hour), time.Time{}, []string{"intern"}, []string{"token"}, 1)

	server := actor.NewActorFromUnsubstantiatedClaims(nil)
	server.SetAuthenticated(mkClaims("zpr.addr", "10.1.0.8", time.Hour), time.Time{}, nil, nil, 1)
	server.SetProvides([]string{"/zpr/testnet/webserver"})

	td := &snip.Traffic{
		Proto:    snip.ProtocolICMP4,
		SrcAddr:  netip.MustParseAddr("10.1.0.20"),
		DstAddr:  netip.MustParseAddr("10.1.0.8"),
		ICMPType: 0x8,
		ICMPCode: 0,
	}

	matches, err := MatchTrafficActors(m, td, client, server)
	require.Nil(t, err)
	require.Len(t, matches, 1)
	match := matches[0]
	require.True(t, match.FWD)
	require.Equal(t, "access", match.CPol.Id)
	require.Equal(t, "/zpr/testnet/webserver", match.CPol.ServiceId)
}

func TestConnectUsingHasKey(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.adapter.cn, has, ""]
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [intern.foo, eq, fee]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t07",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := mkClaims("zpr.addr", "fc00:3001::1", time.Hour)
	claims["zpr.adapter.cn"] = mkClaim("foo", time.Hour)
	client.SetAuthenticated(claims, time.Time{}, nil, nil, 1)

	state, err := policy.NewConnectState(client, nil, netip.Addr{}, logr.NewTestLogger())
	require.Nil(t, err)
	attrs, err := m.MatchConnect(state)
	require.Nil(t, err)
	require.Len(t, attrs, 1)
	require.Contains(t, attrs, "zpr.adapter.cn")
	require.Contains(t, state.Services, "/zpr/testnet/webserver")
}

func TestConnectUsingHasForAccess(t *testing.T) {
	pyml := mtpreamble + network + `
communications:
  systems:
    testnet:
      desc: testnet
      components:
        webserver:
          desc: webserver
          services: [http]
          provider:
            - [zpr.adapter.cn, eq, "web.zpr"]
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [zpr.adapter.cn, has, ""]
        rfcserver:
          desc: rfcserver
          services: [http]
          provider:
            - [zpr.adapter.cn, eq, "rfc.zpr"]
          policies:
            - desc: access
              conditions:
                - desc: all access
                  attrs:
                    - [zpr.adapter.cn, has, ""]
`

	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t07",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	// Now connect a client
	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := mkClaims("zpr.addr", "fc00:3001::1", time.Hour)
	claims["zpr.adapter.cn"] = mkClaim("foo", time.Hour)
	client.SetAuthenticated(claims, time.Time{}, nil, nil, 1)

	state, err := policy.NewConnectState(client, nil, netip.Addr{}, logr.NewTestLogger())
	require.Nil(t, err)
	attrs, err := m.MatchConnect(state)
	require.Nil(t, err)
	require.Len(t, attrs, 1)
	require.Contains(t, attrs, "zpr.adapter.cn")
	require.Empty(t, state.Services)
}

*/

/* TODO: FIX THIS! - Forgot to commit the source zpl (MK has on home computer)

// See https://github.com/org-zpr/zpr-core/issues/746
func TestActorConnectUsingM3Policy(t *testing.T) {
	pfile := filepath.Join("testdata", "oci-m3-full-access.bin")
	cp, err := policy.OpenContainedPolicyFile(pfile, nil)
	require.Nil(t, err)
	p := cp.Policy

	m, err := policy.NewMatcher(p, 1, logr.NewTestLogger())
	require.Nil(t, err)

	// Now connect a client
	client := actor.NewActorFromUnsubstantiatedClaims(nil)
	claims := mkClaims("zpr.addr", "fd5a:5052:2::101", time.Hour)
	claims["zpr.adapter.cn"] = mkClaim("mathias.zpr.org", time.Hour)
	client.SetAuthenticated(claims, time.Time{}, nil, nil, 1)

	state, err := policy.NewConnectState(client, nil, netip.Addr{}, logr.NewTestLogger())
	require.Nil(t, err)
	attrs, err := m.MatchConnect(state)
	require.Nil(t, err)
	require.Len(t, attrs, 1)
	require.Empty(t, state.Services)
}
*/

package policy_test

/* DISABLED UNTIL WE SORT OUT COMPILER

const preamble = `
zpl_format: 2
main:
  policy_version: 1
  policy_date: "2020-10-22T12:23:00Z"

services:
  http:
    tcp: 80
  dsgrpc:
    tcp: 5001
  ping:
    icmp:
      type: request-response
      type_codes: 128, 129
`

const network1 = `
zpr:
  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3
  visaservice:
    provider:
      - [intern.foo, eq, vsvc]
    admin_attrs:
      - [intern.foo, eq, fee]
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [intern.cn, eq, nodus]
      address: "fc00:3001::88"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
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

const network2 = `
zpr:
  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3
  visaservice:
    provider:
      - [intern.foo, eq, vsvc]
    admin_attrs:
      - [intern.foo, eq, fee]
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [intern.cn, eq, nodus]
      address: "fc00:3001::88"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
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
    simplev:
        api: validation/1;query/1
        endpoint:
          provider:
            - [intern.x509.cn, eq, ca-vdator.internal]
          address: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59"
          services:
            - dsgrpc
          tls_domain: auth0.spacelaser.net
          tls_cert:
            encoding: pem
            cert_data: |
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

const network3 = `
zpr:
  globals:
    max_connections: 100
    max_connections_per_dock: 10
    max_connections_per_actor: 3
  visaservice:
    provider:
      - [intern.foo, eq, vsvc]
    admin_attrs:
      - [intern.foo, eq, fee]
  nodes:
    n0:
      key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
      provider:
        - [intern.cn, eq, nodus]
      address: "fc00:3001::88"
      interfaces:
        i0:
          netaddr: "n0.spacelaser.net:5000"
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
    simplev:
        api: validation/1;query/99
        endpoint:
          provider:
            - [intern.x509.cn, eq, ca-vdator.internal]
          address: "fc00:3001:b6ab:4379:488d:9e19:b0d0:8b59"
          services:
            - dsgrpc
          tls_domain: auth0.spacelaser.net
          tls_cert:
            encoding: pem
            cert_data: |
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

const comms = `
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

func compilePolicy(t *testing.T, pyml string) *policy.Policy {
	fs, err := fs.NewMemoryFileStore()
	require.Nil(t, err)
	fs.AddFile("root.yaml", []byte(pyml))
	opts := compiler.CompileOpts{
		Revision: "t01",
		Verbose:  true,
	}
	p, err := compiler.Compile("root.yaml", fs, &opts)
	require.Nil(t, err)
	return policy.NewPolicyFromPol(p, logr.NewTestLogger())
}

func TestDSHashWithDiffDS(t *testing.T) {
	var dshash1, dshash2 []byte

	{
		pp := compilePolicy(t, preamble+network1+comms)
		dshash1 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash1)

	{
		pp := compilePolicy(t, preamble+network2+comms)
		dshash2 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash2)

	require.NotEqual(t, dshash1, dshash2)
}

func TestDSHashWithDiffDSByQueryApiVersion(t *testing.T) {
	var dshash1, dshash2 []byte

	{
		pp := compilePolicy(t, preamble+network2+comms)
		dshash1 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash1)

	{
		pp := compilePolicy(t, preamble+network3+comms)
		dshash2 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash2)

	require.NotEqual(t, dshash1, dshash2)
}

func TestDSHashWithSameDS(t *testing.T) {
	var dshash1, dshash2 []byte

	{
		pp := compilePolicy(t, preamble+network1+comms)
		dshash1 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash1)

	{
		pp := compilePolicy(t, preamble+network1+comms)
		dshash2 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash2)

	require.Equal(t, dshash1, dshash2)
}

func TestDSHashWithSameDSNet2(t *testing.T) {
	var dshash1, dshash2 []byte

	{
		pp := compilePolicy(t, preamble+network2+comms)
		dshash1 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash1)

	{
		pp := compilePolicy(t, preamble+network2+comms)
		dshash2 = pp.GetDatasourceHash()
	}
	require.NotNil(t, dshash2)

	require.Equal(t, dshash1, dshash2)
}

func TestConnectCapatibleNoChange(t *testing.T) {
	pp := compilePolicy(t, preamble+network1+comms)
	require.True(t, pp.IsConnectCompatibleWith(pp))
}

func TestConnectCompatibleWithReducedConnects(t *testing.T) {
	pp := compilePolicy(t, preamble+network1+comms)

	comms2 := strings.Replace(comms, "eq, fee", "eq, horse", 1)
	pq := compilePolicy(t, preamble+network1+comms2)

	require.False(t, pq.IsConnectCompatibleWith(pp))
}

*/

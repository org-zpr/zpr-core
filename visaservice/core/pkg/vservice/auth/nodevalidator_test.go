package auth_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsx/snio/zds"
)

const (
	// Here is the node private key which is used to sign the
	// JWT after authentication succeeds.
	nodePrivateKeyPEM = `
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDqDo2/NjjaoAu2
ULaSfi0EU2vhpGh4A45h1c20rxipwT5JTUPAoHQgnnhsdX8HWklhCmgXl6dd3SOq
7iyhFkNXe2MFCQjh0MdywJkF9+cjLNfkCUTIm1G3csKuJ2fUgFzTzVwtIJb6Qh0o
yZZFvGEydCu8sM75tt4bbfVAFNjEopBzDpZ5QD5sht8qJ+aeWU92fA9lYojOBi2/
6iRgWqegJrfTsCrcc6lFQgi9ntsdxcy48ncbURxoIUtZvS9gSje6lmftm68Sp3n+
wBOpETWtdOkB3uKho9gCK2dHUW6kv1KQwRG7+hxWwMsd/08Vn0pkmhDM2KHuPpz/
CIW1RT9xAgMBAAECggEAAnh3O1vSDsU3wG5iofeEMpaDQKdMDWsWBk8j3+llUnqP
pYWOiTahs9aGYq3cvUCxHk22QUb/QVQdmEmcWxza0WjkEn7YxcJELlr39okaNYvn
nBCouyXFZNvDUC7VF3gyz/nGmajtbQx0UIyXBMBh0IRLR09rYjWG4PMIqWBa9NGL
DL6FiHC/GiZ9iX9K+C+oup0gv0NYlVvgr4SoyU8Nv+3v0LrVuqopXQ6xT2hvql3R
mfIvVNsMQA7drW1Tu1ptRxZ4G2DxLquTCT76RcfqwTHAY16lEKFYcabjg2ud9jbt
IJTuXyATkF4U2RviyPwLLLFybNe3YBtyVYCiLcpnAQKBgQD1d6F0oQ4Yz2IgJRvK
0ZK2pweqfqif1quiYDQ4d2yl71qv97p03fie1NSvAz//9efaXUlu2XE7lxxb0Y+7
di/GJx87FJQqOY3QigxFQtBeGUBpeFRsoKiN6HhDDOngfICQM4AzkmccIAEw0MyD
9oW27sOjYQc4xlwvtDS7feF4cQKBgQD0GZVSB1Zf2D4YetBe8Y6t3WCZ1H063hCd
f9Mq0zGRaby6mbtlBvKfeJoN0d74teiFWGqgq6JkkQwwKWaXlQWt5h1O9yf0QfUI
ssiJ1YTGPLiUrbnCymwnpZOn21eV/aredJOiE0wMSOubX0SkW+CE+ouvPU6ev9qt
ZN4B7Hu3AQKBgQC7QkQ9gRAMBUlKVITbOP2/sbS7cFybc10ERngQC6sq+2oni8kG
lr+wC5Uk3knYrnPttfTrR56GY0UTFs+bpxHTDM1aeNx/SeDSEj5CKDJlVsY4r79Y
D0gG2i3EmPlidBhv6ZoHvcxDPHcsEl2y3kIryAIfhUnJGioBimwgDGwRQQKBgQDF
cvxKAg1oMe7otk9evV6AXRYK2MsDlyUxgXg6p+LskO9MsZXXvqr7O/7BNwZ5gAu5
8S8vECan2nxVaOfHrY+OfxkuCtaSydd/Vb7JX6GrCOr1uSEN49dgqpqpqM9MUIiq
sPnKnHljZojOgV1w5bDTYCcldR3nY6FrqK+8NqJMAQKBgQCcCIpD+WfJrS2tUzQ0
Ya/VH3jtQKWs/ckMym43bZ/SPyYZFLDi+RCKHm/iiIHi7nT+Z7HCh4zRdEBeN3js
83BEgPhEBHot2HUf8FpVs+qIviqFDg/kvpEoIj+tUbPt5nBJNoOt+cjnt6PF6spm
C0XJkkc8hwxl0UP1TtZKdxqdUQ==
-----END PRIVATE KEY-----
	`

	// Here is the cert from the certificate authority.
	caCertPEM = `
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

	// Here is a certificate that includes the agents public key
	// and is signed by the certificate authority.
	agentCertPEM = `
-----BEGIN CERTIFICATE-----
MIID1jCCAr6gAwIBAgIUB/IDuntZN2Yi/0GlTzO4CWskqm0wDQYJKoZIhvcNAQEL
BQAwZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3Zp
bGxlMQswCQYDVQQKDAJBSTEMMAoGA1UECwwDWlBSMRswGQYDVQQDDBJjYTEuc3Bh
Y2VsYXNlci5uZXQwHhcNMjUwMzExMjM0NjMzWhcNMzAwMzEwMjM0NjMzWjBxMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCS1kxDDAKBgNVBAcMA0ZvbzELMAkGA1UECgwC
WlAxCjAIBgNVBAsMAVIxETAPBgNVBAMMCG1hLmhhdG1hMRswGQYJKoZIhvcNAQkB
FgxtYUBoYXRtYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX
I39rAgJbZRiq+31eCl9BDoVeLc1eZ9Nm/fhx4MXXjz7Ml0pZScC5hrYorayV1MUT
mfTDQq/xTWiXVJDvIVx1YeCYUsDcAt5BDUBTz+YbpM4WBXBonh4wBO6mDviVuURD
u1HFuNyYwDrNe+DHPPt3zjC9JJTZYp/mnB4Rx15iMcdFW04tHCzQ05lh9Jivh+wZ
Mo1dxtNVZ3KyYr322e04oIDltWgsz4q1eZFZsS4rELnhw5mVqWARpjdf7WsNkQ6b
O2rSx1DawxTmv0Rmy89FKbXaSUJmSlDW23IcEwCcboxRQKppH6ukdNAbl8QV2kSj
mj8zEtmrReHWYa+7KYwzAgMBAAGjcDBuMB8GA1UdIwQYMBaAFM4wY91a3vUXdEvi
aU7RmbiythFCMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMBQGA1UdEQQNMAuCCSou
enByLm9yZzAdBgNVHQ4EFgQU4PcXp566UvZqYL1kDy52UgQzo0QwDQYJKoZIhvcN
AQELBQADggEBAD0UfJJVmcaNpBJWTmbkYfS45nLY2zwZOruOd1XmPgYgeT6Jb4zq
6aB5Ma6NW5u9FLq9sq0HNdHge44aYrFj8RC1V5FUlQtKKQ6iKFjoyUluKXwO5aYF
J8KZk6Ehp4Mbf5tHZGNP7MQ1Dd/OG57lPnPru+j1uaX/MbujPpgk/7WMOqth3l13
ncn0DlYoFPPrb6OH072AIbUMcy9X29BWCIV8YI06N2oygSba2Z8bP1RTDwOHo/9y
GwI0dptJzXcTnTCOz7n+c/MdInqKxOuddgivM9NQdLnSoAF2xJLsF0H83XM0Imrf
dcwCfDu4D0HGzRYGgfrjxd28BNeYRqQhm0Y=
-----END CERTIFICATE-----
	`

	// Here is the agent private key which is used by the agent
	// to respond to the challenge.
	agentKeyPEM = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXI39rAgJbZRiq
+31eCl9BDoVeLc1eZ9Nm/fhx4MXXjz7Ml0pZScC5hrYorayV1MUTmfTDQq/xTWiX
VJDvIVx1YeCYUsDcAt5BDUBTz+YbpM4WBXBonh4wBO6mDviVuURDu1HFuNyYwDrN
e+DHPPt3zjC9JJTZYp/mnB4Rx15iMcdFW04tHCzQ05lh9Jivh+wZMo1dxtNVZ3Ky
Yr322e04oIDltWgsz4q1eZFZsS4rELnhw5mVqWARpjdf7WsNkQ6bO2rSx1DawxTm
v0Rmy89FKbXaSUJmSlDW23IcEwCcboxRQKppH6ukdNAbl8QV2kSjmj8zEtmrReHW
Ya+7KYwzAgMBAAECggEAFu/iNIE3jltHZRuJqS31ys/DWcmls0AaizTb8ZxlKhOp
Oi9zrx1MTFuvZXkGCi8iQZlJ1iBWx04yI1VIMaJkf8P86+ETN9CPnlu+eXnBuExI
onrs1lO4zRzSgw0emMpnG8hf3pvxjpUN14WHVXVhzIrURsA4fs1C6yKiRZx2LHyZ
m9NI6mxBtCPbKR+Tnb5MrAVIjSPx+nSZP2fG02ycZr1e/foVHH+EHeULfZ7GKuRg
1rrsdmw2EBl1/hLe+ntsvMjKfPlmERNg2Ry59Oz00vdn0Fhi4sR3VnQoQu8GtnFB
H3AMUqTf763l+EyODd9TVmhBOOESttrAaBCR0AlkQQKBgQC2c8AHa4k1yXzaXYGH
wYsDBcFjJ2emEt5QpboHcyXHMdAQylmvd9bBnhtc4ChqVm5sQ2OY3Cd+9yyXfoou
GBaFN14bsSZqqXnwhn5+rsBKuswbAp8nGxuj9QvtmTkuSaffSegnCXXNsj85Ltn9
WkiwFzn4dmh+RfS23Vcx20zMQwKBgQDUEFXQQuh3dL2rLFNwirBnSq3Xu9dmi2nk
vTO/v+VdsOc/44dLnDHb2Cyy8GPcV7v/ZSM6ZZS1L0jSL7cEZrhHY9M89zasXtum
f+xE+0BxjA76VyuX8ZNqPvKBFePrnNqOvehzp7OvMJrbE5f7fJNZ0Z/cdQ1O43Ot
WHS+0vY5UQKBgESJyOpAqEOPVBqHo8AGoZzaDaKcy9/kGKV9DBv+UoO4n6ufB//V
adRD+41xG12O6F49Fm32zdNxMMwcGfZk0BjtCqomawMIdSk4rM4UAWJRN5kx6+15
znFR/VAdDhDoVGqZzd7UO++wdPWbNwJoZwPXRcyjVm+RAfOrxDSTaA8XAoGAEKhn
1UAsOpX1ACkvNLvwN2zqUvPya5+v5cPm+Lz+K2nmAGLDEfFnCTnl6PhxH7HUlq8/
ISsxjznzom8VFUdsWk9BHJzespOQ9Xc++/wwh7rUwl1ukzTqu4HOUs2BZdSgZm4M
gGk/+Bb9UxAq9BpJCNkqkYqwTO4Y/BjissqnhMECgYEApnRHMhXMrLTPOew6xhjA
DplhNiGFRaoJkznrOFA/ULn3mPSrDaxypf5SKsPjGKbFnYMFdv93ITriNwZTKluo
C0yIy/BOUQQqeeSNtryO3IVYyIzN9rZOhJocAj/NVOJiBvqQQYm6/frmrjQ0sxrw
EKMFqayaBkOaZgLEQ8cLjjs=
-----END PRIVATE KEY-----
	`
)

const CredIDBaseAddress = "fc00:3001::0"

var (
	tlog = logr.NewTestLogger()
)

func AddrFromTextOrPanic(idv string, base string) netip.Addr {
	eid, err := AddrFromText(idv, base)
	if err != nil {
		panic(err)
	}
	return eid
}
func AddrFromText(idv string, base string) (netip.Addr, error) {
	// sha256(ID)
	hsha := sha256.New()
	if _, err := hsha.Write([]byte(idv)); err != nil {
		return netip.Addr{}, err
	}
	h256 := hsha.Sum(nil)
	return addrFromData(h256, base), nil
}
func addrFromData(data []byte, base string) netip.Addr {
	buf := make([]byte, 8)

	hfnv64 := fnv.New64a()
	hfnv64.Write(data)
	h1 := hfnv64.Sum(nil)
	copy(buf, h1)
	// `buf` now has 8 bytes of hash.

	addr := net.ParseIP(base) // fc00:3001::0

	// Keep the top 8 bytes of the address, put the 8 byte hash'd buffer
	// onto the back.
	copy([]byte(addr)[8:], buf)

	// Now addr byte 0-7 are from the IP we parsed, and 8-15 are the hash.
	// Note there are four unused bytes (set zero) that are reserved.

	zid := [16]byte{}
	copy(zid[:], addr.To16())

	return netip.AddrFrom16(zid)
}

func loadCert(pemdata []byte) *x509.Certificate {
	blk, _ := pem.Decode(pemdata)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

type TCertDB struct {
	Certs map[uint32]*x509.Certificate
}

func (tdb *TCertDB) ListCertificateIDs() []uint32 {
	var ids []uint32
	for k := range tdb.Certs {
		ids = append(ids, k)
	}
	return ids
}

func (tdb *TCertDB) GetCertificate(id uint32) (*x509.Certificate, string, error) {
	if c, ok := tdb.Certs[id]; ok {
		return c, fmt.Sprintf("cert_%d", id), nil
	}
	return nil, "", fmt.Errorf("cert not found")
}

func TestJWTCreateOneCert(t *testing.T) {
	pk, err := snauth.LoadRSAKeyFromPEM([]byte(nodePrivateKeyPEM))
	if err != nil {
		panic(err)
	}
	caCert := loadCert([]byte(caCertPEM))
	conf := map[string]string{
		"key_data":  base64.StdEncoding.EncodeToString([]byte(agentKeyPEM)),
		"cert_data": base64.StdEncoding.EncodeToString([]byte(agentCertPEM)),
	}

	nv := auth.NewNodeValidator(tlog, 20*time.Minute, "nodename", pk)
	cdb := TCertDB{
		Certs: map[uint32]*x509.Certificate{
			22: caCert,
		},
	}
	nodeEpID := AddrFromTextOrPanic("fee", CredIDBaseAddress)

	// GENERATE A CHALLENGE
	ts := time.Now().Format(time.RFC3339)
	rawNonce := make([]byte, 1024)
	snauth.NewNonce(rawNonce)
	chal := zds.Challenge{
		Spec:      snauth.AuthChallengeV1,
		Timestamp: ts,
		Nonce:     rawNonce,
	}

	// RESPOND TO THE CHALLENGE:
	rsam := snauth.NewRSAv2()
	require.NotNil(t, rsam)
	blks, err := rsam.Respond(conf, &chal, 0)
	require.Nil(t, err)

	vreq := zds.ValidateRequest{
		Chal:           &chal,
		ChallengerAddr: nodeEpID.AsSlice(),
		Claims:         map[string]string{"cert_22.x509.cn": "ma.hatma"},
		CrespSet:       blks,
	}

	// VALIDATE THE RESPONSE
	var revokes []*snauth.CredID
	vresp, err := nv.Validate(&vreq, &cdb, revokes)
	require.Nil(t, err)
	require.Equal(t, "", vresp.VResp.GetError())
	require.Equal(t, zds.ValidateResponse_SUCCESS, vresp.VResp.GetStat())
	require.Equal(t, "cert_22", vresp.Prefix)
	require.Nil(t, err)
	jwts := string(vresp.VResp.GetToken())
	require.NotEmpty(t, jwts)

	// Decode the JWT
	parts := strings.Split(jwts, ".")
	require.Equal(t, 3, len(parts)) // JWT has three sections
	parser := jwt.NewParser()
	js, err := parser.DecodeSegment(parts[1])
	require.Nil(t, err)

	jwtClaims := make(map[string]interface{})
	err = json.Unmarshal(js, &jwtClaims)
	require.Nil(t, err)

	require.Equal(t, float64(1), jwtClaims["xsnz"])
	require.Equal(t, "cert:x509:ca1.spacelaser.net", jwtClaims["xsna.0"])
	require.Equal(t, "59:E7:DA:B7:4A:73:E9:A8:C9:AF:BE:8C:91:86:18:7D:5F:7F:94:27", jwtClaims["xsnc.0"])

	require.Equal(t, "ma.hatma", jwtClaims["sub"])
	require.Equal(t, "zpr", jwtClaims["aud"])
	require.Equal(t, "nodename", jwtClaims["iss"])

	// And sets the standard time fields:
	require.NotEmpty(t, jwtClaims["exp"])
	require.NotEmpty(t, jwtClaims["nbf"])
	require.NotEmpty(t, jwtClaims["iat"])
	require.NotEmpty(t, jwtClaims["jti"])
}

func TestRevokeAuthority(t *testing.T) {
	pk, err := snauth.LoadRSAKeyFromPEM([]byte(nodePrivateKeyPEM))
	if err != nil {
		panic(err)
	}
	caCert := loadCert([]byte(caCertPEM))
	caPrint, err := snauth.NewSHA1Fingerprint(caCert.Raw)
	require.Nil(t, err)
	conf := map[string]string{
		"key_data":  base64.StdEncoding.EncodeToString([]byte(agentKeyPEM)),
		"cert_data": base64.StdEncoding.EncodeToString([]byte(agentCertPEM)),
	}

	nv := auth.NewNodeValidator(tlog, 20*time.Minute, "nodename", pk)
	cdb := TCertDB{
		Certs: map[uint32]*x509.Certificate{
			22: caCert,
		},
	}
	nodeEpID := AddrFromTextOrPanic("fee", CredIDBaseAddress)

	// GENERATE A CHALLENGE
	ts := time.Now().Format(time.RFC3339)
	rawNonce := make([]byte, 1024)
	snauth.NewNonce(rawNonce)
	chal := zds.Challenge{
		Spec:      snauth.AuthChallengeV1,
		Timestamp: ts,
		Nonce:     rawNonce,
	}

	// RESPOND TO THE CHALLENGE:
	rsam := snauth.NewRSAv2()
	blks, err := rsam.Respond(conf, &chal, 0)
	require.Nil(t, err)

	vreq := zds.ValidateRequest{
		Chal:           &chal,
		CrespSet:       blks,
		Claims:         map[string]string{"cert_22.x509.cn": "ma.hatma"},
		ChallengerAddr: nodeEpID.AsSlice(),
	}

	revokes := []*snauth.CredID{
		&snauth.CredID{
			CType: snauth.CredIDTypeAuthority,
			ID:    caPrint.String(),
		},
	}

	// VALIDATE THE RESPONSE
	vresp, err := nv.Validate(&vreq, &cdb, revokes)
	require.Equal(t, "key or credential has been revoked", vresp.VResp.GetError())
	require.Equal(t, zds.ValidateResponse_FAIL, vresp.VResp.GetStat())
	require.Nil(t, err)

	// Try again, this time pass in a cert fingerprint that will not match.
	revokes = []*snauth.CredID{
		&snauth.CredID{
			CType: snauth.CredIDTypeAuthority,
			ID:    "DE:AD:BE:EF:00:19:52:E5:32:AF:47:88:2D:5F:A8:78:96:11:FE:B2",
		},
	}
	vresp, err = nv.Validate(&vreq, &cdb, revokes)
	require.Equal(t, "", vresp.VResp.GetError())
	require.Equal(t, zds.ValidateResponse_SUCCESS, vresp.VResp.GetStat())
	require.Nil(t, err)
}

func TestRevokeCertificate(t *testing.T) {
	pk, err := snauth.LoadRSAKeyFromPEM([]byte(nodePrivateKeyPEM))
	if err != nil {
		panic(err)
	}
	caCert := loadCert([]byte(caCertPEM))
	agentCert := loadCert([]byte(agentCertPEM))
	agentPrint, err := snauth.NewSHA1Fingerprint(agentCert.Raw)
	require.Nil(t, err)
	conf := map[string]string{
		"key_data":  base64.StdEncoding.EncodeToString([]byte(agentKeyPEM)),
		"cert_data": base64.StdEncoding.EncodeToString([]byte(agentCertPEM)),
	}

	nv := auth.NewNodeValidator(tlog, 20*time.Minute, "nodename", pk)
	cdb := TCertDB{
		Certs: map[uint32]*x509.Certificate{
			22: caCert,
		},
	}
	nodeEpID := AddrFromTextOrPanic("fee", CredIDBaseAddress)

	// GENERATE A CHALLENGE
	ts := time.Now().Format(time.RFC3339)
	rawNonce := make([]byte, 1024)
	snauth.NewNonce(rawNonce)
	chal := zds.Challenge{
		Spec:      snauth.AuthChallengeV1,
		Timestamp: ts,
		Nonce:     rawNonce,
	}

	// RESPOND TO THE CHALLENGE:
	rsam := snauth.NewRSAv2()
	blks, err := rsam.Respond(conf, &chal, 0)
	require.Nil(t, err)

	vreq := zds.ValidateRequest{
		Chal:           &chal,
		CrespSet:       blks,
		Claims:         map[string]string{"cert_22.x509.cn": "ma.hatma"},
		ChallengerAddr: nodeEpID.AsSlice(),
	}

	revokes := []*snauth.CredID{
		&snauth.CredID{
			CType: snauth.CredIDTypeAuthority,
			ID:    agentPrint.String(),
		},
	}

	// VALIDATE THE RESPONSE
	vresp, err := nv.Validate(&vreq, &cdb, revokes)
	require.Equal(t, "key or credential has been revoked", vresp.VResp.GetError())
	require.Equal(t, zds.ValidateResponse_FAIL, vresp.VResp.GetStat())
	require.Nil(t, err)

	// Try again, this time pass in a cert fingerprint that will not match.
	revokes = []*snauth.CredID{
		&snauth.CredID{
			CType: snauth.CredIDTypeCertificate,
			ID:    "DE:AD:BE:EF:00:19:52:E5:32:AF:47:88:2D:5F:A8:78:96:11:FE:B2",
		},
	}
	vresp, err = nv.Validate(&vreq, &cdb, revokes)
	require.Equal(t, "", vresp.VResp.GetError())
	require.Equal(t, zds.ValidateResponse_SUCCESS, vresp.VResp.GetStat())
	require.Nil(t, err)
}

func TestSelfValidate(t *testing.T) {
	pk, err := snauth.LoadRSAKeyFromPEM([]byte(nodePrivateKeyPEM))
	if err != nil {
		panic(err)
	}

	require.Nil(t, err)

	nv := auth.NewNodeValidator(tlog, 20*time.Minute, "nodename", pk)

	reqAddr := netip.MustParseAddr("fd00:3001::22")
	claims := make(map[string]string)
	claims[agent.KAttrEPID] = reqAddr.String()
	claims[agent.KAttrCN] = "ma.hatma"

	aok, err := nv.SelfAuthenticate(netip.MustParseAddr("fd00:3001::22"), claims, nil)
	require.Nil(t, err)
	require.NotEmpty(t, aok.Identities)
}

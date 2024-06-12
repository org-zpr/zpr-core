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

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vsx/snio/zds"
	"zpr.org/vs/pkg/vservice/auth"
)

const (
	// Here is the node private key which is used to sign the
	// JWT after authentication succeeds.
	nodePrivateKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f2WjFv/J8jPsjdDoE56vGDZWbds8utVIYnptK9lAUEtghD7
vwAYHRNt6n2ynIGmF2A87vITsmBv7RnrOuNforSNdMbASjKl2hFfE8xXOnBNFVYW
ldn79fsHm9inRfta04bnslS14jN9pHvN+v2O3+Gn51OKhbloCMeGE0KgDBiv7RAk
c6x9sCzbwd0iFpybp1HcjXsCT8XhKbtyYTjQSYxl3u3hLfvCMJ6HY4iV6dGsX4E8
QmU0eiUlk7iZgCp/QvpHazz1AU7NgbDy99IbwJPwb2oVhrEMpa1gQmYu30DHnXZ4
i2DKuyG4DEZ0QJ9me71mvbH3y/Q/OUrIwVAqlwIDAQABAoIBAENYWKbXO4BVnV9U
jLiW6oh8rAjKWpNBggsOmDCaHBV1oOQjv4G5u3XetmCsuK9fC2nn6gCi7y+3AWO8
15ai73sDJyxnliIGWdpUVusFd/EYSkBTeUOKxEUXW7sboy19rCFhEGbaS6FvCsAb
jNSA/zTEgE61XJBhIhmLq+7NafhwS47hsWofsqsrKvYMGYjHfNsPTWp9w4gj/r4o
xOG35j74Mf5Zg8tCtTWxXCdz4WQg6CkBk+OUrZV4rTvf+0f7tDXX3t7DvGx2Jflh
1S+gp53KCMr9fLLcldejixycdJqXxJfNXHZ6ND8IO2AkeTvwyv7frIDCLOk6c/WD
dcKwx/ECgYEA84JkQyHTQVQtikrzlboPxTmViCZHXvAxStAi93IK+DeA8MT0Q+iA
927Rpynbcs/vBPXOVpApzWsEc65Ovuaz6kyJzYWEtV1IIqdQ6BlSBDqkVczGt/uy
RBMM5LkxZEbzYJ1E4HnNcQiUpaMZMAwbiAw5CQTwAKDcvuRpbbEVc+0CgYEA7ZUm
uY1lnMwFUeujemsPeiQRAFtqTGPBRi3fpKn1WU3qn01dcXr652E2eetlCCafWn79
XYp7JRI+d5WYh5LYBkZEKWEjFvoctZuXFrnTfsGbuy6nkGXHHhYv7VaCjv32o0bz
lurRyZ+4vhhUEwtob0Hx2kTE08+HAkj8Xieo0BMCgYEA2lnbqc7U7cmbpFwdG+9h
YMqH6TPZ36mlqZ4FHLkoWPb8KemR1qrPqg+28xw3aTZG772yLjDLKyWBMnHkro2U
Ws4S6zWEkFR68Ifzpou93Yjv/vfGYQfTC/PBJf9h6LcuWT3smxTdQTQehoA/f7P7
o/zBz/KbexTDnHCYkQGvaOkCgYBupMyRE3mkCRvdJ+lNZLijgFJuoSQjCT4Eae7C
Z+h8O54trED9TXG1+f79zpORtTL3WTazrn9lJ1byKDgNw2RZn7W0s6k81SQzq480
pTwKxy24gaTFybBuoZSWaniJEVsgdTWSLi+fP4Qw+3GEIQb08Xgp12b24aoVdVoa
m0uyAwKBgQCOR2Gyxb6375foHvGZQzwYGKUjtGaP5IceXHqugaUL6m4VTt5jFPIT
woiGX9vcGvsXeiuqJPgyCykTSX9id+/V6g4s47I4RMS0meUKdKacSEAT067dDxzH
oe0peuWvUuKi2nMqYOIbya9ORTHI35HIkaYYwRJaQKZOitm9v8wIUg==
-----END RSA PRIVATE KEY-----
	`

	// Here is the cert from the certificate authority.
	caCertPEM = `
-----BEGIN CERTIFICATE-----
MIIDijCCAnICCQDvR2uxX2eKJTANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5l
dDEWMBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJu
YWwxFzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vMB4XDTIwMDIyODE5MjMyN1oXDTI1
MDIyNjE5MjMyN1owgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJLWTEOMAwGA1UE
BwwFVmlsbGUxEDAOBgNVBAoMB3N1cmVuZXQxFjAUBgNVBAsMDWF1dGhvcml6YXRp
b24xFzAVBgNVBAMMDmF1dGgwLmludGVybmFsMRcwFQYJKoZIhvcNAQkBFghhdXRo
QGZvbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCxt6RgI11Q3aZa
DTUp6Q+5uMB+fqhhuaPoeqEZYujgLbeJrldMQ2aIHlqntC1y4tPSCCYriVRS5j6V
cqgtu3saFsA/8MwAvaeY5LmD8wE7fl4b/MGst86FVyD3TLlTt5FDIkhJK+jpgKf1
4NjGDBYSiYVuZ54Kxg8HQXPGXx5txjTxmcBY44b5g5ARxOVu/u/ut0ZeS3z2Uf7K
q4cZ2/C+xxpYo+NMgg3sfuUDfMDAhLymfmWGa5SEj8XCUoYZv3bJLUDjMLtB06yo
alxQowZovSpUdJOjb0e+B8FvaziwRVohQ4Y1hEpx9X/idvwgHxzGzR9mSax+iz+p
OUbw3TMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAChfVONalJLlRCgbqC9gxjhYq
3fA3E4r9yVVlWQmkx8XTK4Z2NWqSdE5PmaYQdvdnzMAsxGHjxgaN/KH/wctEL+qK
2C7bnaevDBrHTtrVM6UUZfec5eerf7UA1MDKq0BqsaUamhzqxygh9Ei2mrG36+LK
my2Mk/tFcvSOS8tB8Q+gAGDKX/4DshR3aEkIDzqpdmwK8ffxD9sJp8HewjNtO3Pv
nsdyXmJ65z95DU5GIsshL7og94933hCN/b86R9Zq6/RAoAM/87TJFnxCywG39Zr5
GRAzgLWJLdkNEos8XB42MCS7tn/jefKDGquuI625jeARa2eCoJT9yk95pQbuAQ==
-----END CERTIFICATE-----
	`

	// Here is a certificate that includes the agents public key
	// and is signed by the certificate authority.
	agentCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEJjCCAw6gAwIBAgIJAMSVUe6Pd/ZwMA0GCSqGSIb3DQEBCwUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjAwMzEyMTczMDA4
WhcNMjUwMzExMTczMDA4WjBYMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxDjAM
BgNVBAcMBVZpbGxlMQswCQYDVQQKDAJTTjEMMAoGA1UECwwDU2VjMREwDwYDVQQD
DAhtYS5oYXRtYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVrs/Wi
EayiBWxX3Wo8vpGQojKD5lgyYmlurtecTcpRB+UbFIP8Jm75VDVn9C4WW5Gi6IeJ
mp0O5tr3xWrwNhdiLuwLQmoyTTNoFJSxz0q6Ym+khdClEVK04aEGmPL7zusSOi8d
E1pCN3sHi3w37mPgPyAXw32J1fjNHT5nRBidN3UchmkFIQ4RYjmKw8VErDL39oYZ
+D50QwxPwQlszbP5CFYIfdaMqJU+puiiW/NJ6oqAQt3Y1gQtI26ZxpwEHy0f0Aoh
m4g6CDLfj+RmXCg/JO5O9PFb9u2mU7khQEEOjW2bzc2lHfZbEdnp1VlYqxDqH38K
Dm4XtoM/gYEagisCAwEAAaOBwzCBwDCBpQYDVR0jBIGdMIGaoYGMpIGJMIGGMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQK
DAdzdXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRo
MC5pbnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb2+CCQDvR2uxX2eKJTAJ
BgNVHRMEAjAAMAsGA1UdDwQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAgR4eKI5B
FK8LnIGay0yuHE+s+L7GV42SiwfGNgGoPzuQpxLmQGuQEJE5Tjn2tEGEA+kVQWUQ
QKSa+KArGgPqUj1C3V5RvwTZ+82QZni79Pmuysw5cErw27Cv8Fydh1aorFEqgGF6
eyq0kge1QnLiBlc2sKm6N2LsJPcf47M6ZbbgrvAhb8ThktinhM4fT4R8oQ5yhGJ3
mJo56YQ5Hxfgi7p89AySEQXhhx4FH+Cs6QIvT0R01tH73b5NPvjDLEEehjTEl+Tl
Acmc3J4RAkZubwNjrLRdcLAfrd5bCsbG5Bb5qR5WWgsa/ZghBSwdrC5J1p028gCD
txHEvCEG978xlg==
-----END CERTIFICATE-----
	`

	// Here is the agent private key which is used by the agent
	// to respond to the challenge.
	agentKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxWuz9aIRrKIFbFfdajy+kZCiMoPmWDJiaW6u15xNylEH5RsU
g/wmbvlUNWf0LhZbkaLoh4manQ7m2vfFavA2F2Iu7AtCajJNM2gUlLHPSrpib6SF
0KURUrThoQaY8vvO6xI6Lx0TWkI3eweLfDfuY+A/IBfDfYnV+M0dPmdEGJ03dRyG
aQUhDhFiOYrDxUSsMvf2hhn4PnRDDE/BCWzNs/kIVgh91oyolT6m6KJb80nqioBC
3djWBC0jbpnGnAQfLR/QCiGbiDoIMt+P5GZcKD8k7k708Vv27aZTuSFAQQ6NbZvN
zaUd9lsR2enVWVirEOoffwoObhe2gz+BgRqCKwIDAQABAoIBAQCZVDEM0bcQcTXt
E8DvxgXsYHzY5wB794XfhQteghMY0x5inkmsyKXBAvyYDgjj0pGD5xbaTdE7slsy
LcWybKZWOvdedNA8Up0LFAcIBaGN1HynYQxdJBb0OXAT9F/OOCxY/msaNGbXbx5P
+2gmLfqEr6HXdx1p3yfEeOoBkYqd4f+U4phVqkDKgjy0J06dIy90PLhl0I1wyorA
R9U36pV/k/iUVDBzDrA9uCRtjJ2j5TfQBmlumTNm7+U7mcDjtrVklYkN5v+jC1p0
rXYgciATGKRCdYaj3A+7O/nU4pXdUYZ2D2ZwEN7uzJvPLdq5ntUtSaBkVSdKUBe2
XPmXlWmBAoGBAOwMSCGlWXUkx3yjsvEnZc+8oFSNR2ZWZuRUFlMKBHvuu/pQ+O+d
eANgBltDwE/2vNHmLZL+DRxhIBwxMD36BnkCfWxfXFD5WlIVAWItujmJRdieUaXr
mDJzMuQlLloWFgm6ycfSr7vgGmk4QF3fTDOHQfuglx9sPkZ28GQt36wxAoGBANYb
lg/yMLLeRNnnqZPyf1apQoF4Beod2PcZLfR3gyEiejuBOXUKB33lP9lYjO6hyPfx
r2cpwYkSWLX8fzfkcTNbfGYGELm9RVG6chyA0MmSt+sRMU7Qep72RyaqmXYXdaDu
j6bn6Q5RV1GFq22+Cg8QojeN8xYeeu8PXQ50h6kbAoGAAQFAYVxJ2DTS4JX10g7/
4PWFnTaIwkfF4lz1R184i6qFhFhJ5wM9mo4TGNpd/Dkprp8TPJf2SFOlhlkzQmBJ
HMTE8ewqAXI+TzEls1xMeag68uQhptos6LIS2mPKIboMV/hCmaYs91jJ4/7IT13+
/g0qW77gRdL5JOWmulZzqFECgYEAhbNyUQDfUkMkYaKdraqnxBksU6b8oocC/sL1
hIzBEQbzp4b5t1GM/hwTdAks8LOMyPBepSBZH9yaEwLa+q8n1XdSxm8RMLu1tuSj
75KtTsLVIPB6hwn/GJcYNVghPrJFnTp78DEvwuYejeTX+U7L/z5W3jRBUVW1VOWW
KbmxIXMCgYEAu95GrgFvYjp6PARJEyHcpUZ7IG5Gcbx2tX4xHArmUn56td+ot1WI
f8yqExJKjFsPwCpGDfD5xHnFGjf8iWhKVfBP7LF9yExp85MzA8Ti2JAa5ykcRBLJ
6Rpq5wBOFhFtfHQi0+m5XVI4WLoH0r99q3mPENZ7yaylaVQ0Fgqkeis=
-----END RSA PRIVATE KEY-----
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
	js, err := jwt.DecodeSegment(parts[1])
	require.Nil(t, err)

	jwtClaims := make(map[string]interface{})
	err = json.Unmarshal(js, &jwtClaims)
	require.Nil(t, err)

	require.Equal(t, float64(1), jwtClaims["xsnz"])
	require.Equal(t, "cert:x509:auth0.internal", jwtClaims["xsna.0"])
	require.Equal(t, "3A:ED:61:17:C3:19:52:E5:32:AF:47:88:2D:5F:A8:78:96:11:FE:B2", jwtClaims["xsnc.0"])
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

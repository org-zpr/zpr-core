package vservice_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"

	"zpr.org/vsx/polio"
)

// This authority cert signed the `nodeNoiseCert` below, but
// not the `testCert`.
const caCert = `-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIUZmqseCk0yvfYsSuno6obs5J5SwAwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNYXV0aG9yaXR5LnpwcjAeFw0yNDEwMDMxODExNTVaFw0z
MjEyMjAxODExNTVaMBgxFjAUBgNVBAMMDWF1dGhvcml0eS56cHIwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVUeqWTv6rAqVnTsCTez4U6oWSeWIWQIV2
ePEYTWGMhCkA95jooowipxyvzw/s8xDvPvZVEqo2I2Y7DavgSk0djXyfWr2JNlzF
IoZ0tx00kKJB74jDG38zQyqhC5C5Qb5jzJEF0S98qCUcFFiHtErdxa7tKi9AZRBv
8MW0j7VRfrC0wGiaCewOJI1kzdVEtXWNBXBBRLvDmY/u40jpeQ3qrjF0ADLOdg2w
idbxDxNK6lUbbZ/w0EA/VvFOLknl2wbx+0tAqExekpUggA/es4PbdSBqC8uo+b93
s2Q3VSIPIsD/d2CDB9eHRayHlE0TNOVF0qgFlOlemmd0CvwOUWF5AgMBAAGjYDBe
MB0GA1UdDgQWBBREqP/S3VYrojelr2Vea01E8+kItDAfBgNVHSMEGDAWgBREqP/S
3VYrojelr2Vea01E8+kItDAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAWNR2Awbn2SibaoPdyGDoDbqK2A/DCiulr4Fk0599
F74Nitt4teil5yOvplaVCrPdgyzPZlrUZXcY4ubZt7VYmL8R2Sn65/VgiOugPGoX
bkdD2nImKhvyCg/5evQ7KgIdonslBc4+BPJidBDkzAOtstbrMZ4lp6ktL7lwKeoG
6uo1lqJ1SoM3JkAizYrzFp6F35OXnQ8giULhYd0GOlmu4LZH1dLfCXz0jGZS8Mxu
fmINTxbSu3f6+zSkcSmun/61Qc7VcBGYcIo1U4gXuvpx9PRrorRvpXBoDYVRe4kx
MjsQAKGjSiTv9RSRX9mBhsg49YeS/JMXEkWZO+S/Wjuw8A==
-----END CERTIFICATE-----`

const nodeNoiseCert = `
-----BEGIN CERTIFICATE-----
MIICETCB+qADAgECAhRmhbwsq9blyxg3Xv5jTvvsJu9/GzANBgkqhkiG9w0BAQsF
ADAYMRYwFAYDVQQDDA1hdXRob3JpdHkuenByMB4XDTI0MTAwMzE5NTQxN1oXDTI1
MTAwMzE5NTQxN1owFzEVMBMGA1UEAwwMbm9kZS56cHIub3JnMCowBQYDK2VuAyEA
GExPGh5RE/nKo8WoN8EqknDDNIEjWBL6PZm08Uhvn0yjTzBNMAsGA1UdDwQEAwID
CDAdBgNVHQ4EFgQUC/Iy9kW1XLoVaA2HYBKqeuiTWNYwHwYDVR0jBBgwFoAURKj/
0t1WK6I3pa9lXmtNRPPpCLQwDQYJKoZIhvcNAQELBQADggEBAG8UlDbtKi6HBLxD
CRgc9LEo80oN0xNme3f/4CMVHOIQnCSVRdgJs4ZhsAnC0rAYam114xeHScb33Irh
nAGd5LdH+X1HpybgS68j9LLfv+waPtSu4EqITOpFKjyOOPhsU0xbHiv2jATcSaQQ
/+n6LMti5MIJyLdiKEwwoPpCRNOBcpELtvrqZKui3sOeauXHcf4hxMcfvcwlypqj
IbgoFcYvTXzozxPIxzpnN+sCFi1FrEI+1ficUQy1Y9q0XM5zv0IF7htI3BE8eu6z
vyUd02GeTskiSa4qzRVh0qG2tcj/FyepN82qII6Lt7xoWEa005T3aaFOcSD2tzzn
s5JVZ48=
-----END CERTIFICATE-----`

const testCert = `-----BEGIN CERTIFICATE-----
MIIEWzCCA0OgAwIBAgIJAMSVUe6Pd/Z7MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCS1kxDjAMBgNVBAcMBVZpbGxlMRAwDgYDVQQKDAdz
dXJlbmV0MRYwFAYDVQQLDA1hdXRob3JpemF0aW9uMRcwFQYDVQQDDA5hdXRoMC5p
bnRlcm5hbDEXMBUGCSqGSIb3DQEJARYIYXV0aEBmb28wHhcNMjQwNjE4MTQzMjI4
WhcNMjUwNjE4MTQzMjI4WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCS1kxCzAJ
BgNVBAoMAllZMQswCQYDVQQLDAJaWjEVMBMGA1UEAwwMdGVzdG5vZGUuenByMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk0x4ui48znwmmnbeVrRMXeiz
DdR2EKbZwsoW/sfePCTa50UJHgA3vPPTGhJTTfjJrVyp2nazpaBuy66h85PQWS2x
FqstxHVTj0+CF4t+YKUyHFZiF2rLWQonO5R43v489NF9JHKH2SgxKMjTsPpJY8sd
yFgUTbiD6G8T/j/ZIojBIkQG2wWNpdjqUDnzeaU32MGHV8iigUrpc3xDqw+RWhKP
kPjoyInoA4tNNrfHrddu61w3FPx6KTN1L8UV9K+BlNW/s3buluYMSi2vW24fjdTn
F3ev2+w+QUcvWP94/pFRiLEDAO+LO3hxFC16qNU33LMvAo8BdJvPG3GbN2+fIwID
AQABo4IBBDCCAQAwgaUGA1UdIwSBnTCBmqGBjKSBiTCBhjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAktZMQ4wDAYDVQQHDAVWaWxsZTEQMA4GA1UECgwHc3VyZW5ldDEW
MBQGA1UECwwNYXV0aG9yaXphdGlvbjEXMBUGA1UEAwwOYXV0aDAuaW50ZXJuYWwx
FzAVBgkqhkiG9w0BCQEWCGF1dGhAZm9vggkA70drsV9niiUwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwHwYDVR0RBBgwFoIUYXV0aDAuc3BhY2VsYXNlci5uZXQwHQYD
VR0OBBYEFFdtDdU6IP12wNv4YUdyZejdx8EaMA0GCSqGSIb3DQEBBQUAA4IBAQBp
gM2xMYgo6ntaPTV7xhLmAbwlhoKBt3I+i6KQUU9Ec/3AEiiZsyQxcPHAtmeU4han
5JpOK3hUYVH/SaSj2BHqkXH0yfFyIkAf0V1UsfWwcD8OEZffb5yP02RzIWCqdBN7
pdx9gtGwy4l779FNvHGQ8AI4y+cpxwiXyBiXdB3Mv1wG5gUNe4pGk7JWA5lb9XQ9
sOwVMjkwcUsqGr489gqYRWl1mAMz1D2T+U91HavGybvUBlgb/3+dgjksa/ZWTUhD
2CRFn7sqmwcPHLoGV/+yCjjuheyx+z7LrPqyqPfWwrr68udK4Yqz8iiqwMC1b8m0
1Hm6nwN1sHYkYgYgk/Ey
-----END CERTIFICATE-----
`

const testPrivakeKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTTHi6LjzOfCaa
dt5WtExd6LMN1HYQptnCyhb+x948JNrnRQkeADe889MaElNN+MmtXKnadrOloG7L
rqHzk9BZLbEWqy3EdVOPT4IXi35gpTIcVmIXastZCic7lHje/jz00X0kcofZKDEo
yNOw+kljyx3IWBRNuIPobxP+P9kiiMEiRAbbBY2l2OpQOfN5pTfYwYdXyKKBSulz
fEOrD5FaEo+Q+OjIiegDi002t8et127rXDcU/HopM3UvxRX0r4GU1b+zdu6W5gxK
La9bbh+N1OcXd6/b7D5BRy9Y/3j+kVGIsQMA74s7eHEULXqo1Tfcsy8CjwF0m88b
cZs3b58jAgMBAAECggEAQYQ8FqPGTBmQmhfRIUOkzAhazAX6VcHBDhERVVXVFW9X
JpLgUUXLhPH2rZwFDaNhIQkcS52MnljTrykHw+21OFVIdUrCWqXM+utkc9CJ77bK
qSwLCVtpAzuu46NQd+8hcctUHEgNAJwN8ZQSBJ/u0MJhhuEWdtNhaJsvi2Ee1WrN
ZvUkpn6SpCHVvEtZjJZL0elQrgk7EMzWSWz/1a8ORzbmBDw5X/0dV/VKCfx1kJ+w
9fmIhfGU3lFT8rOpqcx3MlB+PzRVV4P3hUBirovxBu2TEqp01hvPnb5m6ZGE0U/p
B4LBke3S23iSkYwPaHwcbLVLhF2pruYmXS1hvCZxEQKBgQC3gBWKZZeV8uT0vKN+
FScBk5WLYSq63dUSonszWr0AxN03WsoHjkr4AqB+wtMPI2L7Kpy8whwtTXehqNpT
W+Zz12eVQI2fuGTYZg7zjxN0+H2nRxTOWyVcpW4h1tavzzXAzTDo1jc8DYvMhgXp
IIOMYDbOCQPCnopdE0Xd2QF7NQKBgQDNftHfeNOINkt3RTTI5NY9pTibl/alzqJf
aW8BXEsnKM8BB6ux/sTNE4ejaK7a4xvKhgss+Z0FkM11Ycoa2D5/X9CyXT/cOmhF
E2vt6yyQUSscMQMAaUmma8Gvu5dDF3a7/5liphjafPyFRa275JIxdbDgaCvV62kH
EjPLMjOj9wKBgQCHhe9iwVlNA5EZN2DAM7sVLPybbe3zCPbexmWbLf683KhMw57G
Kc8wkDAcrqLWYVovCe+scOgChV4/ZMeqHQt8rq/vyTdPqQ3BzM5qD1ddYlDbBGJX
bXWQkRVfpJ32RmD6vhDLRbqRfaesK6ed38eIG18emAXQ7Opfh2ZoTGcNqQKBgDKN
/53lwMyi5t/506mUuqxByHJm6VQTSNkGPDvuc8K3hG2xcGkCz3HQWy81YscQ1lZ1
sawn4Jxs6k71dt4x0vZNIS+wRzSr3dkYlRXcJIOApIVz/VQNkwPxQJ42HVlxHVHU
6OxfBoBB/XHgGYS/D8RBOvmKRzaCir0lmj5kJFYzAoGBAKEEaHn0LvmDpHYSUOA4
FgJnFmtHTHcYFaFus/oqwEtylftAsM5h8o5ww2OCJDa2FSxzaayV1wpm2r1HwvDn
p/oYQcQrtBHsdvdZ/8IRR7/9HJNanbhTuKdkdmVjt4rPoUDc2zqzEZUEG33E2Glh
+VS382WYhn8T/WeSmWHmF69D
-----END PRIVATE KEY-----
`

const testPolicyYaml = `
        zpl_format: 2
        services:
          http:
            tcp: 80
        zpr:
          visaservice:
            provider:
              - ["zpr.adapter.cn", eq, vs.zpr]
            admin_attrs:
              - ["zpr.adapter.cn", eq, admin.zpr]
          nodes:
            n0:
              key: "cffa793530e6d63e560e8b314b5035db34aaae324f63cb76b204d3e4c00d5a1a"
              provider:
                - [zpr.adapter.cn, eq, node.zpr.org]
              address: "fc00:3001::8"
              interfaces:
                i0:
                  netaddr: "n0.spacelaser.net:5000"
              services: [http]
              policies: # ERROR - not that this policy applies to all services on the node.
                - desc: web access
                  conditions:
                     - desc: cn is set to fee
                       attrs:
                          - [zpr.adapter.cn, eq, fee]
                  constraints:
                    duration: 90s

          datasources:
            zpr.adapter:
              api: validation/1
              authority:
                encoding: pem
                cert_data: $import[ca0-cert.pem]

        communications:
          systems:
            mathiasland:
              desc: mathiasland
`

// No connect validation.
func initVisaservice(t *testing.T) *vservice.VSInst {
	return initVisaserviceWithOpts(t, newDefaultVSConfig(t))
}

func newDefaultVSConfig(t *testing.T) *vservice.VSIConfig {
	authcert, err := snauth.LoadCertFromPEMBuffer([]byte(caCert))
	require.Nil(t, err)
	return &vservice.VSIConfig{
		Log:                   logr.NewTestLogger(),
		CN:                    "vs.zpr",
		VSAddr:                netip.MustParseAddr(vservice.VisaServiceAddress),
		HopCount:              99,
		AllowInvalidPeerAddr:  true,
		BootstrapAuthDuration: 1 * time.Hour,
		AuthorityCert:         authcert,
	}
}

func initVisaserviceWithOpts(t *testing.T, vcfg *vservice.VSIConfig) *vservice.VSInst {
	svc, err := vservice.NewVSInst(vcfg)
	require.Nil(t, err)
	require.NotNil(t, svc)

	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		authKey)

	svc.SetAuthSvc(authsvc)
	return svc
}

func TestThriftHello(t *testing.T) {
	svc := initVisaservice(t)

	resp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}
	require.Equal(t, int32(0), resp.Challenge.ChallengeType)
	require.Equal(t, 32, len(resp.Challenge.ChallengeData))
}

func createMilestone2HMAC(nonce []byte, sid int32, timestamp int64) [32]byte {
	var msg bytes.Buffer
	msg.Write(nonce)
	binary.Write(&msg, binary.BigEndian, uint64(timestamp))
	binary.Write(&msg, binary.BigEndian, sid)
	return sha256.Sum256(msg.Bytes())
}

// Debug func to print connect rules to stdout.
func printPolicyConnects(plcy *polio.Policy) {
	fmt.Printf("DUMPING POLICY CONNECT RULES:\n")
	for i, cp := range plcy.Connects {
		fmt.Printf("connect rule %d\n", i)
		for _, ae := range cp.AttrExprs {
			fmt.Printf("  %v %v %v\n", plcy.AttrKeyIndex[ae.Key], ae.Op, plcy.AttrValIndex[ae.Val])
		}
	}
	fmt.Printf("DUMPED %v POLICY CONNECT RULES\n", len(plcy.Connects))
}

/* DISABLED UNTIL WE SORT OUT COMPILER

func TestThriftRegister(t *testing.T) {
	svc := initVisaservice(t)

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(testPolicyYaml))
		fst.AddFile("/ca0-cert.pem", []byte(caCert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)
		alog := logr.NewTestLogger()
		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	timestamp := time.Now().Unix()

	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, helloResp.SessionID, timestamp)

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     netip.MustParseAddr("fc00:3001::8").AsSlice(),
		TetherAddr:  netip.MustParseAddr("fc00:3001::8").AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	apiKey, err := svc.Authenticate(context.Background(), authReq)
	require.Nil(t, err)
	require.NotEmpty(t, apiKey)

	time.Sleep(500 * time.Millisecond)

	err = svc.DeRegister(context.Background(), apiKey)
	require.Nil(t, err)
}

*/

func TestThriftRegisterNullChallenge(t *testing.T) {
	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	timestamp := time.Now().Unix()

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     netip.MustParseAddr("fc00:3001::8").AsSlice(),
		TetherAddr:  netip.MustParseAddr("fc00:3001::8").AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: nil,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      []byte("foo"),
		NodeActor: agnt,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "challenge required")
}

func TestThriftRegisterNoFakeHello(t *testing.T) {
	svc := initVisaservice(t)

	fakeHelloResp := new(vsapi.HelloResponse)
	fakeHelloResp.SessionID = 12345

	nonce := make([]byte, snauth.ChallengeNonceSize)
	snauth.NewNonce(nonce)
	fakeHelloResp.Challenge = &vsapi.Challenge{
		ChallengeType: 0,
		ChallengeData: nonce,
	}

	// create HMAC(nonce + timestamp + session_id)
	timestamp := time.Now().Unix()
	sig := createMilestone2HMAC(fakeHelloResp.Challenge.ChallengeData, fakeHelloResp.SessionID, timestamp)

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     netip.MustParseAddr("fc00:3001::8").AsSlice(),
		TetherAddr:  netip.MustParseAddr("fc00:3001::8").AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: fakeHelloResp.SessionID,
		Challenge: fakeHelloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	_, err := svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "invalid session ID")
}

func TestThriftRegisterInvalidSig(t *testing.T) {
	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	timestamp := time.Now().Unix()

	// bad session id
	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, 1679, timestamp)

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     netip.MustParseAddr("fc00:3001::8").AsSlice(),
		TetherAddr:  netip.MustParseAddr("fc00:3001::8").AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "failed to verify HMAC")
}

func TestThriftRegisterNullActor(t *testing.T) {
	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}
	timestamp := time.Now().Unix()
	// create HMAC(nonce + timestamp + session_id)
	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, helloResp.SessionID, timestamp)

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "actor is required")
}

func TestThriftDeRegisterNoKeyNoCrash(t *testing.T) {
	svc := initVisaservice(t)
	err := svc.DeRegister(context.Background(), "nokey")
	require.ErrorIs(t, err, vsapi.NewUnauthorizedError())
	err = svc.DeRegister(context.Background(), "")
	require.ErrorIs(t, err, vsapi.NewUnauthorizedError())
}

/* DISABLED UNTIL WE SORT OUT COMPILER

func TestThriftPollRespectKey(t *testing.T) {
	svc := initVisaservice(t)

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(testPolicyYaml))
		fst.AddFile("/ca0-cert.pem", []byte(caCert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)
		alog := logr.NewTestLogger()
		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	// create HMAC(nonce + timestamp + session_id)
	timestamp := time.Now().Unix()
	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, helloResp.SessionID, timestamp)

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     netip.MustParseAddr("fc00:3001::8").AsSlice(),
		TetherAddr:  netip.MustParseAddr("fc00:3001::8").AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	apiKey, err := svc.Authenticate(context.Background(), authReq)
	require.Nil(t, err)
	require.NotEmpty(t, apiKey)

	// Poll should succeed.
	{
		pr, err := svc.Poll(apiKey)
		require.Nil(t, err)
		require.Empty(t, pr.Visas)
		require.Empty(t, pr.Revocations)
	}

	// Poll should fail with wrong API key.
	{
		_, err := svc.Poll(apiKey + "foo")
		require.NotNil(t, err)
		require.ErrorContains(t, err, "Unauthorized")
	}

	// And if we deregister, poll should fail even with right API key.
	svc.DeRegister(context.Background(), apiKey)
	{
		_, err := svc.Poll(apiKey)
		require.NotNil(t, err)
		require.ErrorContains(t, err, "Unauthorized")
	}
}

*/

/* TODO: Fix me - need to recompile test test policy

// This time prepare a "real" connection request. Will not fail
// because we can not yet enable acutal actor challenge validation.
// So this will succeed.
//
// See `initVisaservice` where we turn off connect validation.
func TestThriftAuthorizeConnectRealRequest(t *testing.T) {
	svc := initVisaservice(t)

	{
		// We cannot use our ZPL in here since to run this
		// sort of connect we need to use boostrap which is
		// not supported by the old ZPL compiler.

		pfile := filepath.Join("auth", "testdata", "vs-auth-test.bin")
		cp, err := policy.OpenContainedPolicyFile(pfile, nil)
		require.Nil(t, err)
		polplcy := cp.Policy
		plcy := policy.NewPolicyFromPol(polplcy, logr.NewTestLogger())
		svc.InstallPolicy(1234, 0, plcy)
	}

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	// create HMAC(nonce + timestamp + session_id)
	timestamp := time.Now().Unix()
	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, helloResp.SessionID, timestamp)

	nodeAddr := netip.MustParseAddr("fd5a:5052:90de::1")
	dockAddr := netip.MustParseAddr("fd5a:5052:90de::1")

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     nodeAddr.AsSlice(),
		TetherAddr:  dockAddr.AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/node.zpr.org")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	apiKey, err := svc.Authenticate(context.Background(), authReq)
	require.Nil(t, err)
	require.NotEmpty(t, apiKey)

	// Clearly, the only thing we can connect is a visa service.

	actorClaims := map[string]string{
		"zpr.addr":       vservice.VisaServiceAddress,
		"zpr.adapter.cn": "vs.zpr",
	}

	nonce := make([]byte, snauth.ChallengeNonceSize)
	snauth.NewNonce(nonce)

	// The policy in auth/testdata has a public key for bootstrap init.
	pkey, err := snauth.LoadRSAKeyFromFile(filepath.Join("auth", "testdata", "vs.zpr_key.pem"))
	require.Nil(t, err)

	blob := auth.NewZdpSelfSignedBlobUnsiged("vs.zpr", nonce)
	err = blob.Sign(pkey)
	require.Nil(t, err)

	zchalresps := make([][]byte, 1)
	blobbuf, err := blob.Encode()
	require.Nil(t, err)
	zchalresps[0] = []byte(blobbuf)

	req := vsapi.ConnectRequest{
		ConnectionID:       99,
		DockAddr:           dockAddr.AsSlice(),
		Claims:             actorClaims,
		Challenge:          nil, // unused
		ChallengeResponses: zchalresps,
	}
	cr, err := svc.AuthorizeConnect(context.Background(), apiKey, &req)
	require.Nil(t, err)
	require.Equal(t, req.ConnectionID, cr.ConnectionID)
	require.Equal(t, vsapi.StatusCode_SUCCESS, cr.Status)
	require.NotNil(t, cr.Actor)
}

*/

/* DISABLED UNTIL WE SORT OUT COMPILER

func TestThriftRequestVisaNoRouteToHost(t *testing.T) {

	svc := initVisaservice(t)

	{
		// Compile and install the policy
		fst, _ := fs.NewMemoryFileStore()
		fst.AddFile("/pol.yaml", []byte(testPolicyYaml))
		fst.AddFile("/ca0-cert.pem", []byte(caCert))

		opts := &compiler.CompileOpts{
			Revision: "foo1",
			Verbose:  true,
		}
		plcy, err := compiler.Compile("/pol.yaml", fst, opts)
		require.Nil(t, err)
		require.NotNil(t, plcy)
		alog := logr.NewTestLogger()
		pp := policy.NewPolicyFromPol(plcy, alog)
		svc.InstallPolicy(policy.InitialConfiguration, 1, pp)
	}

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	// create HMAC(nonce + timestamp + session_id)
	timestamp := time.Now().Unix()
	sig := createMilestone2HMAC(helloResp.Challenge.ChallengeData, helloResp.SessionID, timestamp)

	nodeZprAddr := netip.MustParseAddr("fc00:3001::8")
	nodeTetherAddr := nodeZprAddr

	agnt := &vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		AuthExpires: time.Now().Unix() + 11400, // +4hrs
		ZprAddr:     nodeZprAddr.AsSlice(),
		TetherAddr:  nodeTetherAddr.AsSlice(),
		Ident:       uuid.New().String(),
	}
	agnt.Provides = append(agnt.Provides, "/zpr/n0")

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(nodeNoiseCert),
		Hmac:      sig[:],
		NodeActor: agnt,
	}

	apiKey, err := svc.Authenticate(context.Background(), authReq)
	require.Nil(t, err)
	require.NotEmpty(t, apiKey)

	actorTetherAddr := netip.MustParseAddr("fc00:3003::5:10")
	actorContactAddr := netip.MustParseAddr("fc00:3001::10:20")

	pktbuf := gopacket.NewSerializeBuffer()

	createPacket(pktbuf, actorContactAddr, nodeZprAddr, 31337, 22)

	vr, err := svc.RequestVisa(context.Background(), apiKey, actorTetherAddr.AsSlice(), 6, pktbuf.Bytes())
	require.Nil(t, err)
	require.NotNil(t, vr)
	require.Equal(t, vsapi.StatusCode_FAIL, vr.Status)
	require.Contains(t, *vr.Reason, "no route to host")

	// And as usual, wrong key -- no dice
	{
		_, err := svc.RequestVisa(context.Background(), apiKey+"foo", actorTetherAddr.AsSlice(), 6, pktbuf.Bytes())
		require.NotNil(t, err)
		require.ErrorContains(t, err, "Unauthorized")
	}
}

*/

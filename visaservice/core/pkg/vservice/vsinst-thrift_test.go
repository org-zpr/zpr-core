package vservice_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vs/pkg/vservice"
)

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

func initVisaservice(t *testing.T) *vservice.VSInst {
	alog := logr.NewTestLogger()
	/*
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
	*/
	vc := minVSI(t, 99, alog)
	svc, err := vservice.NewVSInst(vc)
	require.Nil(t, err)
	require.NotNil(t, svc)
	svc.SetAuthSvc(&TestAS{})
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

func TestThriftRegister(t *testing.T) {
	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)
	rng := rand.Reader

	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	// create HMAC(nonce + timestamp + session_id)

	var buf bytes.Buffer

	timestamp := time.Now().Unix()

	buf.Write(helloResp.Challenge.ChallengeData)
	binary.Write(&buf, binary.BigEndian, uint64(timestamp))
	binary.Write(&buf, binary.BigEndian, helloResp.SessionID)
	hashed := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	require.Nil(t, err)

	agnt := &vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
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
		NodeCert:  []byte(testCert),
		Hmac:      sig,
		NodeAgent: agnt,
	}

	apiKey, err := svc.Authenticate(context.Background(), authReq)
	require.Nil(t, err)
	require.NotEmpty(t, apiKey)

	time.Sleep(500 * time.Millisecond)

	err = svc.DeRegister(context.Background(), apiKey)
	require.Nil(t, err)
}

func TestThriftRegisterNullChallenge(t *testing.T) {
	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	timestamp := time.Now().Unix()

	agnt := &vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
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
		NodeCert:  []byte(testCert),
		Hmac:      []byte("foo"),
		NodeAgent: agnt,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "challenge required")
}

func TestThriftRegisterNoFakeHello(t *testing.T) {
	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)
	rng := rand.Reader

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

	var buf bytes.Buffer

	timestamp := time.Now().Unix()

	buf.Write(fakeHelloResp.Challenge.ChallengeData)
	binary.Write(&buf, binary.BigEndian, uint64(timestamp))
	binary.Write(&buf, binary.BigEndian, fakeHelloResp.SessionID)
	hashed := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	require.Nil(t, err)

	agnt := &vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
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
		NodeCert:  []byte(testCert),
		Hmac:      sig,
		NodeAgent: agnt,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "invalid session ID")
}

func TestThriftRegisterInvalidSig(t *testing.T) {
	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)
	rng := rand.Reader

	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	var buf bytes.Buffer

	timestamp := time.Now().Unix()

	buf.Write(helloResp.Challenge.ChallengeData)
	// Fail to add in the other data... so sig will not match
	hashed := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	require.Nil(t, err)

	agnt := &vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
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
		NodeCert:  []byte(testCert),
		Hmac:      sig,
		NodeAgent: agnt,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "failed to verify HMAC")
}

func TestThriftRegisterNullAgent(t *testing.T) {
	privateKey, err := snauth.LoadRSAKeyFromPEM([]byte(testPrivakeKey))
	require.Nil(t, err)
	rng := rand.Reader

	svc := initVisaservice(t)

	helloResp, err := svc.Hello(context.Background())
	if err != nil {
		t.Fatalf("Hello failed: %v", err)
	}

	// create HMAC(nonce + timestamp + session_id)

	var buf bytes.Buffer

	timestamp := time.Now().Unix()

	buf.Write(helloResp.Challenge.ChallengeData)
	binary.Write(&buf, binary.BigEndian, uint64(timestamp))
	binary.Write(&buf, binary.BigEndian, helloResp.SessionID)
	hashed := sha256.Sum256(buf.Bytes())
	sig, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	require.Nil(t, err)

	authReq := &vsapi.NodeAuthRequest{
		SessionID: helloResp.SessionID,
		Challenge: helloResp.Challenge,
		Timestamp: timestamp,
		NodeCert:  []byte(testCert),
		Hmac:      sig,
	}

	_, err = svc.Authenticate(context.Background(), authReq)
	require.ErrorContains(t, err, "agent is required")
}

func TestThriftDeRegisterNoKeyNoCrash(t *testing.T) {
	svc := initVisaservice(t)
	err := svc.DeRegister(context.Background(), "nokey")
	require.ErrorIs(t, err, vsapi.NewUnauthorizedError())
	err = svc.DeRegister(context.Background(), "")
	require.ErrorIs(t, err, vsapi.NewUnauthorizedError())
}

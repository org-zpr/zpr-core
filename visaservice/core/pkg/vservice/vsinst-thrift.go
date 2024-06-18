package vservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net/netip"
	"time"

	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vsx/snio/vsio"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/google/uuid"
)

const (
	HelloTimeout = 2 * time.Minute
	MaxClockSkew = 5 * time.Minute
)

// And sets vs.thiftServer reference.
func (vs *VSInst) startThriftBlocking(listenAddr netip.Addr, port uint16) error {

	var transport thrift.TServerTransport
	var err error

	transport, err = thrift.NewTServerSocket(fmt.Sprintf("%v:%d", listenAddr, port))
	if err != nil {
		return err
	}

	processor := vsapi.NewVisaServiceProcessor(vs)
	transportFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), nil)
	protocolFac := thrift.NewTBinaryProtocolFactoryConf(nil)

	server := thrift.NewTSimpleServer4(processor, transport, transportFac, protocolFac)

	vs.thriftServer = server
	return server.Serve()
}

// Returns 0 if unable to get a session ID
func (vs *VSInst) nextHelloSession(chksum uint32) int32 {
	vs.sessions.Lock()
	defer vs.sessions.Unlock()

	for i := 0; i < 10; i++ {
		sid := rand.Int31()
		if sid == 0 {
			continue
		}
		if hrec, ok := vs.sessions.hellos[sid]; !ok {
			vs.sessions.hellos[sid] = &HelloRecord{
				Chksum: chksum,
				CTime:  time.Now(),
			}
			return sid
		} else {
			if time.Since(hrec.CTime) > HelloTimeout {
				vs.sessions.hellos[sid] = &HelloRecord{
					Chksum: chksum,
					CTime:  time.Now(),
				}
			}
		}
	}
	return 0
}

// Returns TRUE if the session ID was found and checksum matches and not expired.
func (vs *VSInst) freeSessionID(sid int32, chksum uint32) bool {
	vs.sessions.Lock()
	defer vs.sessions.Unlock()

	if hrec, ok := vs.sessions.hellos[sid]; ok {
		if hrec.Chksum == chksum {
			delete(vs.sessions.hellos, sid)
			return time.Since(hrec.CTime) < HelloTimeout
		}
	}
	return false
}

func (vs *VSInst) takePeerRecord(key string) *PeerRecord {
	vs.sessions.Lock()
	defer vs.sessions.Unlock()
	if pr, ok := vs.sessions.apiKeys[key]; ok {
		delete(vs.sessions.apiKeys, key)
		return pr
	}
	return nil
}

func verifyHMAC(pubKey *rsa.PublicKey, nonce []byte, sid int32, timestamp int64, sig []byte) error {
	var msg bytes.Buffer

	msg.Write(nonce)
	binary.Write(&msg, binary.BigEndian, uint64(timestamp))
	binary.Write(&msg, binary.BigEndian, sid)

	hashed := sha256.Sum256(msg.Bytes())
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return err
	}
	return nil
}

func vsapiAgentToVsioAgent(a *vsapi.Agent) *vsio.Agent {

	vsa := new(vsio.Agent)
	vsa.Authenticated = false
	vsa.AuthExpires = time.Unix(a.AuthExpires, 0).Format(time.RFC3339)

	vsa.AuthClaims = make(map[string]*vsio.AClaim)
	for k, v := range a.Attrs {
		vsa.AuthClaims[k] = &vsio.AClaim{Cval: v, Exp: a.AuthExpires}
	}

	if zaddr, ok := netip.AddrFromSlice(a.ZprAddr); ok {
		vsa.AuthAddr = zaddr.AsSlice()
		vsa.TetherAddr = zaddr.AsSlice()
	}

	vsa.Ident = a.Ident
	vsa.Provides = append(vsa.Provides, a.Provides...)

	return vsa
}

// ===================================== THRIFT API ========================= //

func (vs *VSInst) Hello(ctx context.Context) (*vsapi.HelloResponse, error) {
	chal := new(vsapi.Challenge)
	chal.ChallengeType = 0
	chal.ChallengeData = make([]byte, snauth.ChallengeNonceSize)
	snauth.NewNonce(chal.ChallengeData)

	resp := new(vsapi.HelloResponse)
	resp.Challenge = chal
	resp.SessionID = vs.nextHelloSession(crc32.ChecksumIEEE(chal.ChallengeData))
	if resp.SessionID == 0 {
		return nil, fmt.Errorf("unable to get a session ID")
	}
	return resp, nil
}

func (vs *VSInst) Authenticate(ctx context.Context, req *vsapi.NodeAuthRequest) (string, error) {
	if req.Challenge == nil {
		vs.log.Warn("registration: missing challenge")
		return "", fmt.Errorf("challenge required")
	}

	if !vs.freeSessionID(req.SessionID, crc32.ChecksumIEEE(req.Challenge.ChallengeData)) {
		return "", fmt.Errorf("invalid session ID")
	}

	vs.log.Info("registration: authenticate for node -- skipping authority check (TODO)")
	// TODO ...

	if time.Since(time.Unix(req.Timestamp, 0)).Abs() > MaxClockSkew {
		vs.log.Warn("registration: authenticate for node -- timestamp is too old", "timestamp", req.Timestamp,
			"diff", time.Since(time.Unix(req.Timestamp, 0)))
		return "", fmt.Errorf("timestamp is too old")
	}

	if req.NodeAgent == nil {
		vs.log.Warn("registration: authenticate for node -- missing node agent")
		return "", fmt.Errorf("agent is required")
	}

	pubKey, err := snauth.LoadRSAPublicKeyFromPEMBuffer(req.NodeCert)
	if err != nil {
		vs.log.WithError(err).Warn("registration: failed to read public key from cert")
		return "", fmt.Errorf("failed to load public key from cert")
	}

	if err = verifyHMAC(pubKey, req.Challenge.ChallengeData, req.SessionID, req.Timestamp, req.Hmac); err != nil {
		vs.log.WithError(err).Warn("registration: authenticate for node -- failed to verify HMAC")
		return "", fmt.Errorf("failed to verify HMAC")
	}

	// 4. now we can consider the details in the nodeAgnet.
	//    Do we know of this node?  The node must be in our policy, right?
	//    Need to add a "record" that this node has connected.
	vs.log.Info("registration: TODO - check that we want this node, etc")

	// TODO: Need to fix this a bit. We used to rely on the nodes to keep the RAFT
	//       database of connected entities.  But we are moving that function (probably
	//       without raft) to the visa service.  So here I need to tell visa serice
	//       that this node (the passed agent) is now connected.

	naddr, ok := netip.AddrFromSlice(req.NodeAgent.ZprAddr)
	if !ok {
		vs.log.Warn("registration: node passes invalid ZPR address", "addr", req.NodeAgent.ZprAddr)
		return "", fmt.Errorf("invalid agent ZPR address")
	}
	vs.AddNode(naddr)

	apiKey := uuid.New().String()

	vs.sessions.Lock()
	defer vs.sessions.Unlock()

	vs.sessions.apiKeys[apiKey] = &PeerRecord{
		Agent:            vsapiAgentToVsioAgent(req.NodeAgent),
		RegistrationTime: time.Now(),
	}

	return apiKey, nil
}

func (vs *VSInst) DeRegister(ctx context.Context, key string) error {
	rec := vs.takePeerRecord(key)
	if rec == nil {
		vs.log.Warn("registration: de-register called with invalid key", "key", key)
		return nil
	}
	naddr, addrOk := netip.AddrFromSlice(rec.Agent.AuthAddr)
	if !addrOk {
		vs.log.Warn("registration: de-register but agent record has invalid address", "addr", rec.Agent.AuthAddr)
		return nil
	}
	vs.log.Info("de-register", "node_addr", naddr, "visa_requests", rec.VisaRequestsCount, "connects", rec.ConnectRequestsCount)
	vs.RemoveNode(naddr)
	return nil
}

func (vs *VSInst) AuthorizeConnect(ctx context.Context, key string, request *vsapi.ConnectRequest) (*vsapi.ConnectResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (vs *VSInst) Poll(ctx context.Context, key string) (*vsapi.PollResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (vs *VSInst) RequestVisa(ctx context.Context, key string, srcTetherAddr []byte, traffic *vsapi.TrafficDesc) (*vsapi.VisaResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

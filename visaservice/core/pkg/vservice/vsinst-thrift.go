package vservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net/netip"
	"time"

	"zpr.org/vs/pkg/agent"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vsapi"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/google/uuid"
)

const (
	HelloTimeout = 2 * time.Minute
	MaxClockSkew = 5 * time.Minute
)

// Start the thrift server (and set the `VSInst.thriftServer` pointer).
//
// TODO: This is not using eny encyrption on the thrift connection.
func (vs *VSInst) startThriftBlocking(listenAddr netip.Addr, port uint16) error {

	var transport thrift.TServerTransport
	var err error

	ap := netip.AddrPortFrom(listenAddr, port)
	vs.log.Info("starting THRIFT server", "addr", ap.String(), "TLS_enabled?", "no")
	transport, err = thrift.NewTServerSocket(ap.String())
	if err != nil {
		return fmt.Errorf("failed to create THRIFT socket: %w", err)
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

// Removes and returns the PeerRecord from the apikeys table.  After this the API key is no longer valid.
func (vs *VSInst) takePeerRecord(key string) (netip.Addr, *PeerRecord) {
	var naddr netip.Addr
	vs.sessions.Lock()
	if addr, ok := vs.sessions.apiKeys[key]; ok {
		delete(vs.sessions.apiKeys, key)
		naddr = addr
	}
	vs.sessions.Unlock()

	var peer *PeerRecord
	vs.agentDB.Lock()
	defer vs.agentDB.Unlock()
	if rec, ok := vs.agentDB.agents[naddr]; ok {
		if rec.Peer != nil {
			peer = rec.Peer
			rec.Peer.APIKey = ""
		}
	}

	return naddr, peer
}

func (vs *VSInst) validAPIKey(key string) bool {
	vs.sessions.RLock()
	defer vs.sessions.RUnlock()
	_, ok := vs.sessions.apiKeys[key]
	return ok
}

func (vs *VSInst) nodeAddrForKey(key string) (netip.Addr, bool) {
	vs.sessions.RLock()
	defer vs.sessions.RUnlock()
	addr, ok := vs.sessions.apiKeys[key]
	return addr, ok
}

func (vs *VSInst) validAPIKeyAndDeets(key string) (bool, time.Time, netip.Addr) {
	var nodeAddr netip.Addr
	found := false
	vs.sessions.RLock()
	if rec, ok := vs.sessions.apiKeys[key]; ok {
		nodeAddr = rec
		found = true
	}
	vs.sessions.RUnlock()

	if found {
		vs.agentDB.RLock()
		defer vs.agentDB.RUnlock()
		if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
			if rec.Peer != nil {
				return true, rec.Peer.LastPollTime, nodeAddr
			}
		}
	}

	return false, time.Time{}, netip.Addr{}
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

func vsapiTrafficDescToIpTraffic(pd *vsapi.TrafficDesc) *snip.Traffic {
	tcpflags := uint16(pd.GetFlags())
	syn := (tcpflags & 0x0002) > 0
	ack := (tcpflags & 0x0010) > 0

	saddr, _ := netip.AddrFromSlice(pd.GetSource())
	daddr, _ := netip.AddrFromSlice(pd.GetDest())

	var icmpa netip.Addr
	if ica := pd.GetIcmpAddr(); ica != nil {
		icmpa, _ = netip.AddrFromSlice(ica)
	}
	return &snip.Traffic{
		SrcAddr:           saddr,
		DstAddr:           daddr,
		Proto:             snip.Protocol(pd.GetProtocol()),
		SrcPort:           uint16(pd.SourcePort),
		DstPort:           uint16(pd.DestPort),
		Connect:           syn && !ack,
		Syn:               syn,
		Fin:               (tcpflags & 0x0001) > 0,
		Rst:               (tcpflags & 0x0004) > 0,
		Urg:               (tcpflags & 0x0020) > 0,
		Psh:               (tcpflags & 0x0008) > 0,
		Ack:               ack,
		ICMPType:          byte(pd.GetIcmpType()),
		ICMPCode:          byte(pd.GetIcmpType()),
		ICMPTargetAddress: icmpa,
		Size:              int(pd.GetSize()),
		Flags:             uint32(pd.Flags),
	}
}

// --------------------------------- BACKDOOR ------------------------------- //
//
// These functions are used by unit tests to get agents into the visa service.
//
// TODO: This is placeholder code until I find a cleaner way to do this.
//

// returns API key
func (vs *VSInst) BackDoorInstallAPIKeyForUnitTest(node_addr netip.Addr, node_name string) (string, error) {
	return vs.BackDoorInstallAPIKeyForUnitTestExp(node_addr, node_name, time.Now().Add(5*time.Minute))
}

// returns API key
func (vs *VSInst) BackDoorInstallAPIKeyForUnitTestExp(node_addr netip.Addr, node_name string, expiration time.Time) (string, error) {
	apiKey, err := vs.finishAuthenticate(node_addr, expiration, []string{fmt.Sprintf("/zpr/%s", node_name)}, "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	return apiKey, nil
}

func (vs *VSInst) BackDoorConnectAdapter(tether_addr netip.Addr, zpr_addr netip.Addr, dock_addr netip.Addr, extra_claims map[string]*agent.ClaimV, expiration time.Time) error {
	return vs.BackDoorConnectSvcAdapter(tether_addr, zpr_addr, dock_addr, extra_claims, nil, expiration)
}

func (vs *VSInst) BackDoorConnectSvcAdapter(tether_addr netip.Addr, zpr_addr netip.Addr, dock_addr netip.Addr, extra_claims map[string]*agent.ClaimV, provides []string, expiration time.Time) error {
	_, _, cid := vs.getPolicyMatcherConfig()

	claims := make(map[string]*agent.ClaimV)
	claims[agent.KAttrEPID] = agent.NewClaimV(zpr_addr.String(), expiration)
	claims[agent.KAttrRole] = agent.NewClaimV("adapter", expiration)
	claims[agent.KAttrConnectVia] = agent.NewClaimV(dock_addr.String(), expiration)

	for k, v := range extra_claims {
		claims[k] = v
	}

	agnt := agent.EmptyAgent()
	if len(provides) > 0 {
		agnt.SetProvides(provides)
	}
	agnt.SetTetherAddr(tether_addr)
	agnt.SetAuthenticated(claims, expiration, nil, nil, cid)

	return vs.AddAdapter(zpr_addr, agnt)
}

// --------------------------------- BEGIN THRIFT ------------------------------- //

func (vs *VSInst) Hello(ctx context.Context) (*vsapi.HelloResponse, error) {
	// TODO: Would be nice to know address of client...
	vs.log.Debug("*HELLO*")
	chal := new(vsapi.Challenge)
	chal.ChallengeType = vsapi.CHALLENGE_TYPE_HMAC_SHA256
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
	vs.log.Debug("*AUTHENTICATE*")
	if req.Challenge == nil {
		vs.log.Warn("registration: missing challenge")
		return "", fmt.Errorf("challenge required")
	}

	if !vs.freeSessionID(req.SessionID, crc32.ChecksumIEEE(req.Challenge.ChallengeData)) {
		return "", fmt.Errorf("invalid session ID")
	}

	vs.log.Info("registration: authenticate for node -- skipping authority check (TODO)")
	// TODO: check that the certificate is signed by our authority.

	if time.Since(time.Unix(req.Timestamp, 0)).Abs() > MaxClockSkew {
		vs.log.Warn("registration: authenticate for node -- timestamp is too old", "timestamp", req.Timestamp,
			"diff", time.Since(time.Unix(req.Timestamp, 0)))
		return "", fmt.Errorf("timestamp is too old")
	}

	if req.NodeAgent == nil {
		vs.log.Warn("registration: authenticate for node -- missing node agent")
		return "", fmt.Errorf("agent is required")
	}

	if req.NodeAgent.AgentType != vsapi.AgentType_NODE {
		vs.log.Warn("registration: authenticate for node -- invalid agent type", "type", req.NodeAgent.AgentType)
		return "", fmt.Errorf("invalid agent type")
	}

	if len(req.NodeAgent.Provides) < 1 {
		// The node-agent must at least provide /zpr/<node-name>
		vs.log.Warn("registration: authenticate for node -- missing provides")
		return "", fmt.Errorf("missing provides")
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

	//    Now we can consider the details in the nodeAgnet.
	//    Do we know of this node?  The node must be in our policy, right?
	//    Need to add a "record" that this node has connected.
	vs.log.Info("registration: TODO - check that we want this node, etc")

	// TODO: Need to fix this a bit. We used to rely on the nodes to keep the RAFT
	//       database of connected entities.  But we are moving that function (probably
	//       without raft) to the visa service.  So here I need to tell visa serice
	//       that this node (the passed agent) is now connected.
	//
	// For now I am fabricating a node-agent here.  Eventually the node will reun through
	// the ZDP authentication steps to establish proper credentials.

	expiration := time.Now().Add(1 * time.Hour)
	naddr, ok := netip.AddrFromSlice(req.NodeAgent.ZprAddr)
	if !ok {
		vs.log.Warn("registration: node passes invalid ZPR address", "addr", req.NodeAgent.ZprAddr)
		return "", fmt.Errorf("invalid agent ZPR address")
	}

	var vssServiceAddr string

	if req.VssService == "" {
		ap := netip.AddrPortFrom(naddr, VSSDefaultPort)
		vssServiceAddr = ap.String()
		vs.log.Info("registration: missing VSS service address - using default", "vss_addr", vssServiceAddr)
	} else {
		vssServiceAddr = req.VssService
		vs.log.Info("registration: got VSS service address", "vss_addr", vssServiceAddr)
	}

	apiKey, err := vs.finishAuthenticate(naddr, expiration, req.NodeAgent.Provides, vssServiceAddr)
	if err != nil {
		vs.log.WithError(err).Warn("registration: failed to write to agent DB")
		return "", fmt.Errorf("internal error")
	}

	vs.vsMsgC <- &VSMsg{
		MsgType:  MTNodeRegister,
		NodeAddr: naddr,
	}

	return apiKey, nil
}

func (vs *VSInst) finishAuthenticate(naddr netip.Addr, expiration time.Time, provides []string, vssServiceAddr string) (string, error) {
	_, _, cid := vs.getPolicyMatcherConfig()

	claims := make(map[string]*agent.ClaimV)
	claims[agent.KAttrEPID] = agent.NewClaimV(naddr.String(), expiration)
	claims[agent.KAttrRole] = agent.NewClaimV("node", expiration)

	nodeAgent := agent.EmptyAgent()
	nodeAgent.SetProvides(provides)
	nodeAgent.SetTetherAddr(naddr)
	nodeAgent.SetAuthenticated(claims, expiration, nil, nil, cid)

	if err := vs.AddNode(naddr, nodeAgent); err != nil {
		return "", err
	}

	apiKey := uuid.New().String()

	vs.sessions.Lock()
	vs.sessions.apiKeys[apiKey] = naddr
	vs.sessions.Unlock()

	peer := &PeerRecord{
		APIKey:           apiKey,
		RegistrationTime: time.Now(),
		VSSAddr:          vssServiceAddr,
	}
	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[naddr]; ok {
		rec.Peer = peer
	} else {
		vs.log.Warn("registration: node not found in agent DB", "addr", naddr)
	}
	vs.agentDB.Unlock()

	return apiKey, nil
}

func (vs *VSInst) DeRegister(ctx context.Context, key string) error {
	vs.log.Debug("*DE_REGISTER*")
	naddr, rec := vs.takePeerRecord(key)
	if rec == nil {
		vs.log.Debug("registration: de-register called with invalid key", "key", key)
		return vsapi.NewUnauthorizedError()
	}
	vs.log.Info("de-register", "node_addr", naddr, "visa_requests", rec.VisaRequestsCount, "connects", rec.ConnectRequestsCount)
	vs.RemoveNode(naddr)
	return nil
}

func (vs *VSInst) AuthorizeConnect(ctx context.Context, key string, request *vsapi.ConnectRequest) (*vsapi.ConnectResponse, error) {
	vs.log.Debug("*AUTHORIZE_CONNECT*")
	if !vs.validAPIKey(key) {
		vs.log.Debug("agent-disconnect called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}

	if naddr, ok := vs.nodeAddrForKey(key); ok {
		vs.agentDB.Lock()
		if rec, ok := vs.agentDB.agents[naddr]; ok {
			if rec.Peer != nil {
				rec.Peer.ConnectRequestsCount++
			}
		}
		vs.agentDB.Unlock()
	}

	// Note that the prototype visa service allowed a node to pass itself (its own agent) in to this call,
	// and in that case we pass it in to approve connection which ends up just accepting the nodes
	// credentials without checking.  I don't think we need or want that for ref-impl, but the arg is still
	// there on the ApproveConnection function but we set it nil below.
	resp, err := vs.ApproveConnection(request, nil)
	if err != nil {
		strerr := err.Error()
		resp = &vsapi.ConnectResponse{
			ConnectionID: request.ConnectionID,
			Status:       vsapi.StatusCode_FAIL,
			Reason:       &strerr,
		}
		vs.log.WithError(err).Info("authorize connect fails")
	} else if resp.Status != vsapi.StatusCode_SUCCESS {
		vs.log.Info("authorize connect fails", "reason", resp.Reason)
	} else {
		vs.log.Info("authorize connect succeeds", "agent_ident", resp.Agent.Ident)
	}
	return resp, nil
}

func (vs *VSInst) AgentDisconnect(ctx context.Context, key string, zprAddr []byte) error {
	vs.log.Debug("*AGENT_DISCONNECT*")
	if !vs.validAPIKey(key) {
		vs.log.Debug("agent-disconnect called with invalid key", "key", key)
		return vsapi.NewUnauthorizedError()
	}
	zaddr, addrOk := netip.AddrFromSlice(zprAddr)
	if !addrOk {
		vs.log.Warn("registration: de-register but agent record has invalid address", "addr", zprAddr)
		return nil
	}
	vs.log.Info("agent disconnect", "zpr_addr", zaddr)

	// Normally this would be an adapter disconnect.
	isNode := false
	found := false
	vs.agentDB.RLock()
	if rec, ok := vs.agentDB.agents[zaddr]; ok {
		isNode = rec.Agent.GetRole() == "node"
		found = true
	}
	vs.agentDB.RUnlock()

	if !found {
		vs.log.Warn("agent-disconnect called but address not found", "addr", zaddr)
		return nil
	}
	if !isNode {
		vs.RemoveAdapter(zaddr)
		return nil
	}

	// Hmm -- is a node.  I would expect a node to call DeRegister instead.  But we will
	// de-register this node too.
	vs.log.Info("agent-disconnect: de-registering a node", "addr", zaddr)
	return vs.DeRegister(ctx, key)
}

// Poll is not really necessary anymore since we can just use the visa-support-service.
func (vs *VSInst) Poll(ctx context.Context, key string) (*vsapi.PollResponse, error) {
	vs.log.Debug("*POLL*")
	valid, lastPoll, zprAddr := vs.validAPIKeyAndDeets(key)
	if !valid {
		vs.log.Debug("poll called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}
	if lastPoll.IsZero() {
		vs.log.Info("first poll", "peer", zprAddr)

		vs.agentDB.Lock()
		if rec, ok := vs.agentDB.agents[zprAddr]; ok {
			if rec.Peer != nil {
				rec.Peer.LastPollTime = time.Now()
			}
		}
		vs.agentDB.Unlock()
	}

	var messages []*vsapi.PollResponse
	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[zprAddr]; ok {
		if rec.Peer != nil {
			messages = rec.Peer.PushBuffer
			rec.Peer.PushBuffer = nil
		}
	}
	vs.agentDB.Unlock()

	resp := vsapi.PollResponse{}

	for _, msg := range messages {
		resp.Visas = append(resp.Visas, msg.Visas...)
		resp.Revocations = append(resp.Revocations, msg.Revocations...)
	}

	return &resp, nil
}

func (vs *VSInst) RequestVisa(ctx context.Context, key string, srcTetherAddr []byte, traffic *vsapi.TrafficDesc) (*vsapi.VisaResponse, error) {
	vs.log.Debug("*REQUEST_VISA*")
	valid, _, zprAddr := vs.validAPIKeyAndDeets(key)
	if !valid {
		vs.log.Debug("poll called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}

	vs.log.Info("request visa", "peer", zprAddr)

	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[zprAddr]; ok {
		if rec.Peer != nil {
			rec.Peer.VisaRequestsCount++
		}
	}
	vs.agentDB.Unlock()

	pp := vs.getPolicy() // take & release lock
	pver := uint64(0)
	if pp != nil {
		pver = pp.VersionNumber()
	}
	tetherAddr, ok := netip.AddrFromSlice(srcTetherAddr)
	if !ok {
		return nil, errors.New("invalid tether address on visa request")
	}
	vsResp, err := vs.doRequestVisa(ctx, tetherAddr, vsapiTrafficDescToIpTraffic(traffic), 0, pver)

	if err != nil {
		e := err.Error()
		return &vsapi.VisaResponse{
			Status: vsapi.StatusCode_FAIL,
			Reason: &e,
		}, nil
	}

	return vsResp, nil
}

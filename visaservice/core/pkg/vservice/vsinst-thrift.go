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
	"strings"
	"time"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vservice/adb"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/google/uuid"
)

const (
	HelloTimeout = 2 * time.Minute
	MaxClockSkew = 5 * time.Minute
)

type PollResponse struct {
	Visas       []*vsapi.VisaHop
	Revocations []*vsapi.VisaRevocation
}
type Revocation struct {
	IssuerID uint32
	ConfigID uint64
}

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
func (vs *VSInst) takePeerRecord(key string) (netip.Addr, *adb.PeerRecord) {
	var naddr netip.Addr
	vs.sessions.Lock()
	if addr, ok := vs.sessions.apiKeys[key]; ok {
		delete(vs.sessions.apiKeys, key)
		naddr = addr
	}
	vs.sessions.Unlock()

	vs.actorDB.DisableAPIKey(naddr)
	return naddr, vs.actorDB.GetPeerRecord(naddr)
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

func (vs *VSInst) updateContactTime(key string) {
	var naddr netip.Addr
	found := false
	vs.sessions.RLock()
	if addr, ok := vs.sessions.apiKeys[key]; ok {
		found = true
		naddr = addr
	}
	vs.sessions.RUnlock()
	if !found {
		return
	}

	vs.actorDB.SetNodeContactTime(naddr, time.Now())
}

// Returns (key_is_valid, last_heard_from_time, node_address)
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
		lastContact, ok := vs.actorDB.GetNodeLastContact(nodeAddr)
		if ok {
			return true, lastContact, nodeAddr
		}
	}

	return false, time.Time{}, netip.Addr{}
}

// Older prototype HMAC verification using PKI.
func verifyRsaHMAC(pubKey *rsa.PublicKey, nonce []byte, sid int32, timestamp int64, sig []byte) error {
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

// Milestone2 hmac value is just a HASH_SHA256(nonce + timestamp + sid)
func verifyMilestone2HMAC(nonce []byte, sid int32, timestamp int64, sig []byte) error {
	var msg bytes.Buffer
	msg.Write(nonce)
	binary.Write(&msg, binary.BigEndian, uint64(timestamp))
	binary.Write(&msg, binary.BigEndian, sid)
	hashed := sha256.Sum256(msg.Bytes())
	if !bytes.Equal(hashed[:], sig) {
		return errors.New("HMAC verification failed")
	}
	return nil
}

// --------------------------------- BACKDOOR ------------------------------- //
//
// These functions are used by unit tests to get actors into the visa service.
//
// TODO: This is placeholder code until I find a cleaner way to do this.
//

// returns API key
func (vs *VSInst) BackDoorInstallAPIKeyForUnitTest(node_addr netip.Addr, node_name, vssAddr string) (string, error) {
	return vs.BackDoorInstallAPIKeyForUnitTestExp(node_addr, node_name, time.Now().Add(5*time.Minute), vssAddr)
}

// returns API key
func (vs *VSInst) BackDoorInstallAPIKeyForUnitTestExp(node_addr netip.Addr, node_name string, expiration time.Time, vssAddr string) (string, error) {

	_, _, cid := vs.getPolicyMatcherConfig()

	claims := make(map[string]*actor.ClaimV)
	claims[actor.KAttrEPID] = actor.NewClaimV(node_addr.String(), expiration)
	claims[actor.KAttrRole] = actor.NewClaimV("node", expiration)

	provides := []string{fmt.Sprintf("/zpr/%s", node_name)}

	nodeActor := actor.EmptyActor()
	nodeActor.SetProvides(provides)
	nodeActor.SetTetherAddr(node_addr)
	nodeActor.SetAuthenticated(claims, expiration, nil, nil, cid)

	apiKey, err := vs.finishAuthenticate(node_addr, nodeActor, vssAddr)
	if err != nil {
		return "", err
	}
	return apiKey, nil
}

func (vs *VSInst) BackDoorConnectAdapter(tether_addr netip.Addr, zpr_addr netip.Addr, dock_addr netip.Addr, extra_claims map[string]*actor.ClaimV, expiration time.Time) error {
	return vs.BackDoorConnectSvcAdapter(tether_addr, zpr_addr, dock_addr, extra_claims, nil, expiration)
}

func (vs *VSInst) BackDoorConnectSvcAdapter(tether_addr netip.Addr, zpr_addr netip.Addr, dock_addr netip.Addr, extra_claims map[string]*actor.ClaimV, provides []string, expiration time.Time) error {
	_, _, cid := vs.getPolicyMatcherConfig()

	claims := make(map[string]*actor.ClaimV)
	claims[actor.KAttrEPID] = actor.NewClaimV(zpr_addr.String(), expiration)
	claims[actor.KAttrRole] = actor.NewClaimV("adapter", expiration)
	claims[actor.KAttrConnectVia] = actor.NewClaimV(dock_addr.String(), expiration)

	for k, v := range extra_claims {
		claims[k] = v
	}

	agnt := actor.EmptyActor()
	if len(provides) > 0 {
		agnt.SetProvides(provides)
	}
	agnt.SetTetherAddr(tether_addr)
	agnt.SetAuthenticated(claims, expiration, nil, nil, cid)

	return vs.actorDB.AddOrUpdateAdapter(zpr_addr, agnt.GetTetherAddr(), agnt)
}

// Poll used to be a VS API function, but is superceded by the VSS push functions.
// Left her for unit testing ease.
func (vs *VSInst) Poll(key string) (*PollResponse, error) {
	vs.log.Debug("*POLL*")
	valid, _, zprAddr := vs.validAPIKeyAndDeets(key)
	if !valid {
		vs.log.Debug("poll called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}
	messages := vs.actorDB.DrainPending(zprAddr)
	vcount, rcount := 0, 0
	for _, msg := range messages {
		vcount += len(msg.Visas)
		rcount += len(msg.Revocations)
	}
	vs.log.Debugf("found %d messages (%d visas, %d revocations) in mbox for node %s", len(messages), vcount, rcount, zprAddr)
	resp := PollResponse{}
	for _, msg := range messages {
		resp.Visas = append(resp.Visas, msg.Visas...)
		resp.Revocations = append(resp.Revocations, msg.Revocations...)
	}
	return &resp, nil
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

	nodeCert, err := snauth.LoadCertFromPEMBuffer(req.NodeCert)
	if err != nil {
		vs.log.WithError(err).Warn("registration: authenticate for node -- failed to load node cert")
		return "", fmt.Errorf("failed to parse node certificate")
	}
	if err := nodeCert.CheckSignatureFrom(vs.authorityCert); err != nil {
		vs.log.WithError(err).Error("registration: authenticate for node fails cert authority check")
		return "", fmt.Errorf("certificate authority not recognized")
	}

	if time.Since(time.Unix(req.Timestamp, 0)).Abs() > MaxClockSkew {
		vs.log.Warn("registration: authenticate for node -- timestamp is too old", "timestamp", req.Timestamp,
			"diff", time.Since(time.Unix(req.Timestamp, 0)))
		return "", fmt.Errorf("timestamp is too old")
	}

	if req.NodeActor == nil {
		vs.log.Warn("registration: authenticate for node -- missing node actor")
		return "", fmt.Errorf("actor is required")
	}

	if req.NodeActor.ActorType != vsapi.ActorType_NODE {
		vs.log.Warn("registration: authenticate for node -- invalid actor type", "type", req.NodeActor.ActorType)
		return "", fmt.Errorf("invalid actor type")
	}

	if len(req.NodeActor.Provides) < 1 {
		// The node-actor must at least provide /zpr/<node-name>
		vs.log.Warn("registration: authenticate for node -- missing provides")
		return "", fmt.Errorf("missing provides")
	}

	// For milestone 2 this auth is just placeholder.
	if err = verifyMilestone2HMAC(req.Challenge.ChallengeData, req.SessionID, req.Timestamp, req.Hmac); err != nil {
		vs.log.WithError(err).Warn("registration: authenticate for node -- failed to verify HMAC")
		return "", fmt.Errorf("failed to verify HMAC")
	}

	naddr, ok := netip.AddrFromSlice(req.NodeActor.ZprAddr)
	if !ok {
		vs.log.Warn("registration: node passes invalid ZPR address", "addr", req.NodeActor.ZprAddr)
		return "", fmt.Errorf("invalid actor ZPR address")
	}

	// In prototype, the node calls authorize_connect for ITSELF after registration.
	// That is important as it sets up other services and such that may be on the
	// node.  So let's try invoking that here.
	//
	// We could think about just using boostrap auth for nodes, but that does mean
	// that the node needs an RSA keypair and the public key needs to be in policy.
	// I think our current more ad-hoc scheme just uses a cert which might be more
	// convenient for network admins.
	//
	// TODO: Revisit the HMAC thing in the registration request -- do we need that?
	//
	// It would be nicer if the ApproveConnection call could do the actual auth
	// checking instead of us here.
	//
	// TODO: For now I am passing in a fake self-signed (but unsigned) blob and the "magic"
	// claim of "nodeness" which ApproveConnection will honor (instead of
	// looking into policy to find a public key).
	var realNodeActor *actor.Actor = nil

	vs.log.Debug("registration: running ApproveConnection for node")
	{
		claims := make(map[string]string)
		claims[actor.KAttrEPID] = naddr.String()
		claims[actor.KAttrCN] = nodeCert.Subject.CommonName
		claims[actor.KAttrRole] = "node" // does ApproveConnection set this?

		blob := auth.NewZdpSelfSignedBlobUnsiged(nodeCert.Subject.CommonName, req.Challenge.ChallengeData)
		blobStr, err := blob.Encode()
		if err != nil {
			vs.log.WithError(err).Warn("registration: failed to encode blob")
			return "", fmt.Errorf("failed to encode blob")
		}
		responses := make([][]byte, 1)
		responses[0] = []byte(blobStr)

		// Now this ought to to create a real actor... so if this "works" we need to patch up the finishAuthentication function
		// so we don't overwrite the good actor with a fake one.
		creq := vsapi.ConnectRequest{
			ConnectionID:       1,
			DockAddr:           netip.MustParseAddr("0.0.0.0").AsSlice(),
			Claims:             claims,
			Challenge:          nil,
			ChallengeResponses: responses,
		}

		realNodeActor, err = vs.asyncApproveConnection(&creq)
		if err != nil {
			vs.log.WithError(err).Warn("registration: ApproveConnection failed")
			return "", fmt.Errorf("connection setup failed")
		}

		vs.log.Info("registration: ApproveConnection successful", "actor", realNodeActor)
	}

	// TODO: Need to fix this a bit. We used to rely on the nodes to keep the RAFT
	//       database of connected entities.  But we are moving that function (probably
	//       without raft) to the visa service.  So here I need to tell visa serice
	//       that this node (the passed actor) is now connected.
	//
	// For now I am fabricating a node-actor here.  Eventually the node will reun through
	// the ZDP authentication steps to establish proper credentials.

	var vssServiceAddr string

	if req.VssService == "" {
		ap := netip.AddrPortFrom(naddr, VSSDefaultPort)
		vssServiceAddr = ap.String()
		vs.log.Info("registration: missing VSS service address - using default", "vss_addr", vssServiceAddr)
	} else {
		vssServiceAddr = req.VssService
		if _, err := netip.ParseAddrPort(vssServiceAddr); err != nil {
			vs.log.Warn("registration: invalid VSS service address", "vss_addr", vssServiceAddr)
			return "", fmt.Errorf("invalid VSS service address")
		}
		vs.log.Info("registration: got VSS service address", "vss_addr", vssServiceAddr)
	}

	apiKey, err := vs.finishAuthenticate(naddr, realNodeActor, vssServiceAddr)
	if err != nil {
		vs.log.WithError(err).Warn("registration: failed to write to actor DB")
		return "", fmt.Errorf("internal error")
	}

	vs.vsMsgC <- &VSMsg{
		MsgType:  MTNodeRegister,
		NodeAddr: naddr,
	}

	return apiKey, nil
}

// func (vs *VSInst) finishAuthenticate(naddr netip.Addr, expiration time.Time, provides []string, vssServiceAddr string) (string, error) {
func (vs *VSInst) finishAuthenticate(naddr netip.Addr, nodeActor *actor.Actor, vssServiceAddr string) (string, error) {
	apiKey := uuid.New().String()

	// Becuase ApproveConnection does not add nodes to the database... (TODO: FIXME)
	if err := vs.actorDB.AddNode(naddr, naddr, nodeActor, apiKey, vssServiceAddr); err != nil {
		return "", err
	}

	vs.sessions.Lock()
	vs.sessions.apiKeys[apiKey] = naddr
	vs.sessions.Unlock()

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
	vs.actorDB.RemoveNode(naddr)
	return nil
}

// Latest ref-impl stuffs any authentication BLOBS into the ConnectRequest.ChallengeResponse
// byte buffers.  An authentication BLOB is just a base64 encoded JSON object.
func (vs *VSInst) AuthorizeConnect(ctx context.Context, key string, request *vsapi.ConnectRequest) (*vsapi.ConnectResponse, error) {
	vs.log.Debug("*AUTHORIZE_CONNECT*")
	if !vs.validAPIKey(key) {
		vs.log.Debug("authorize-connect called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}

	if naddr, ok := vs.nodeAddrForKey(key); ok {
		vs.actorDB.IncrNodeConnectReq(naddr)
	}

	// Ensure that claims passed in do not include any sensitive ones.
	scrubbedClaims := make(map[string]string)
	for k, v := range request.Claims {
		if strings.HasPrefix(k, "zpr.") {
			// We allow:
			//    zpr.addr - for requsting an address (temporary) (TODO)
			//    zpr.adapter.cn - CN name determined by node (but must match signed blob too)
			switch k {
			case actor.KAttrEPID, actor.KAttrCN:
				{
					scrubbedClaims[k] = v
				}
			default:
				vs.log.Warn("registration: authorize-connect -- rejected claim", "claim", k, "value", v)
				continue
			}
		} else {
			scrubbedClaims[k] = v
		}
	}

	// Note that the prototype visa service allowed a node to pass itself (its own actor) in to this call,
	// and in that case we pass it in to approve connection which ends up just accepting the nodes
	// credentials without checking.  I don't think we need or want that for ref-impl, but the arg is still
	// there on the ApproveConnection function but we set it nil below.
	var resp *vsapi.ConnectResponse
	agnt, err := vs.asyncApproveConnection(request)
	if err != nil {
		strerr := err.Error()
		resp = &vsapi.ConnectResponse{
			ConnectionID: request.ConnectionID,
			Status:       vsapi.StatusCode_FAIL,
			Reason:       &strerr,
		}
		vs.log.WithError(err).Info("authorize connect fails")
	} else {
		vs.log.Info("authorize connect succeeds", "actor_ident", agnt.GetIdentity())
		resp = &vsapi.ConnectResponse{
			ConnectionID: request.ConnectionID,
			Status:       vsapi.StatusCode_SUCCESS,
			Actor:        actorToVsapiActor(agnt, nil), // TODO: Tether address?
		}
	}
	return resp, nil
}

func (vs *VSInst) ActorDisconnect(ctx context.Context, key string, zprAddr []byte) error {
	vs.log.Debug("*ACTOR_DISCONNECT*")
	if !vs.validAPIKey(key) {
		vs.log.Debug("actor-disconnect called with invalid key", "key", key)
		return vsapi.NewUnauthorizedError()
	}
	vs.updateContactTime(key)
	zaddr, addrOk := netip.AddrFromSlice(zprAddr)
	if !addrOk {
		vs.log.Warn("registration: de-register but actor record has invalid address", "addr", zprAddr)
		return nil
	}
	vs.log.Info("actor disconnect", "zpr_addr", zaddr)

	// Normally this would be an adapter disconnect.
	found := vs.actorDB.Contains(zaddr)
	isNode := vs.actorDB.IsNode(zaddr)

	if !found {
		vs.log.Warn("actor-disconnect called but address not found", "addr", zaddr)
		return nil
	}
	if !isNode {
		vs.actorDB.RemoveAdapter(zaddr)
		return nil
	}

	// Hmm -- is a node.  I would expect a node to call DeRegister instead.  But we will
	// de-register this node too.
	vs.log.Info("actor-disconnect: de-registering a node", "addr", zaddr)
	return vs.DeRegister(ctx, key)
}

func (vs *VSInst) Ping(ctx context.Context, key string) (*vsapi.Pong, error) {
	vs.log.Debug("*PING*")
	valid, _, _ := vs.validAPIKeyAndDeets(key)
	if !valid {
		vs.log.Debug("ping called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}
	vs.updateContactTime(key)
	pp, _, configID := vs.getPolicyMatcherConfig()
	return &vsapi.Pong{
		Configuration: int64(configID),
		PolicyVersion: int64(pp.VersionNumber()),
	}, nil
}

func (vs *VSInst) RequestVisa(ctx context.Context, key string, srcTetherAddr []byte, l3_type int8, traffic []byte) (*vsapi.VisaResponse, error) {
	vs.log.Debug("*REQUEST_VISA*")
	valid, _, zprAddr := vs.validAPIKeyAndDeets(key)
	if !valid {
		vs.log.Debug("poll called with invalid key", "key", key)
		return nil, vsapi.NewUnauthorizedError()
	}
	tetherAddr, ok := netip.AddrFromSlice(srcTetherAddr)
	if !ok {
		return nil, errors.New("invalid tether address on visa request")
	}
	vs.log.Info("request visa", "peer", zprAddr, "src_tether_addr", tetherAddr, "pkt_len", len(traffic))
	vs.actorDB.IncrNodeVisaReq(zprAddr)

	trafficDesc, err := snip.DescribePacket(snip.L3Type(l3_type), traffic)
	if err != nil {
		vs.log.WithError(err).Warn("failed to parse packet")
		return nil, errors.New("unparseable traffic")
	}

	pp := vs.getPolicy() // take & release lock
	pver := uint64(0)
	if pp != nil {
		pver = pp.VersionNumber()
	}
	vs.log.Debug("invoking request-visa for visa service API", "requesting_node", zprAddr)
	vsResp, err := vs.doRequestVisa(ctx, tetherAddr, trafficDesc, 0, pver)

	if err != nil {
		e := err.Error()
		return &vsapi.VisaResponse{
			Status: vsapi.StatusCode_FAIL,
			Reason: &e,
		}, nil
	}

	return vsResp, nil
}

const ApproveConnectionTimeout = 1 * time.Minute

// ApproveConnection is long running and makes calls to various service.
// We submit the task and wait for it to finish or we give up.
func (vs *VSInst) asyncApproveConnection(creq *vsapi.ConnectRequest) (*actor.Actor, error) {
	replyC := make(chan *VSMsgDone)
	vs.vsMsgC <- &VSMsg{
		MsgType:        MTApproveConnection,
		ConnectRequest: creq,
		ReplyC:         replyC,
	}

	select {
	case doneMsg := <-replyC:
		if doneMsg.Err != nil {
			vs.log.WithError(doneMsg.Err).Warn("registration: ApproveConnection failed")
			return nil, fmt.Errorf("connection denied")
		}
		return doneMsg.Actor, nil
	case <-time.After(ApproveConnectionTimeout):
		return nil, fmt.Errorf("connection setup timed out")
	}
}

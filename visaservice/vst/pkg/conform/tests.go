package conform

import (
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/vsapi"
)

const MinChallengeNonceSize = 32
const HelloRepsCount = 100

func RunTest(test ConformanceTest, state *TestState, card *Scorecard) error {
	runf, ok := Runners[test]
	if !ok {
		panic(fmt.Sprintf("undefined test: %v", test))
	}

	ctest := card.Start(test)
	if err := runf(state, ctest); err != nil {
		// Automatically fail if error returned, but we do not automatically pass if nil returned.
		ctest.Failed(err)
		return err
	}
	return nil
}

func pause() {
	time.Sleep(2 * time.Second)
}

// If this works, it stores the current policy in the state.
func RunGetCurrentPolicy(state *TestState, ctest *TestRun) error {
	if err := loadPolicy(state); err != nil {
		ctest.Failed(err)
		return nil
	}
	ctest.Passed()
	return nil
}

func RunHelloReps(state *TestState, ctest *TestRun) error {
	reps := HelloRepsCount
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}
	sids := make(map[int32]bool)
	dupeCount := 0
	state.log.Infow("testing hello from node", "reps", reps)
	for i := 0; i < reps; i++ {
		resp, err := mockNode.Hello()
		if err != nil {
			ctest.Failedm(fmt.Sprintf("hello failed at rep %d: %w", i, err))
			return nil
		}
		if sids[resp.SessionID] {
			dupeCount++
		} else {
			sids[resp.SessionID] = true
		}
	}
	if dupeCount > 0 {
		state.log.Warnw("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	} else {
		state.log.Infow("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	}

	ctest.Passed()
	return nil
}

// Check challenge results from the visa service
func RunCheckChallenge(state *TestState, ctest *TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}

	// NODE->VS : Hello
	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}

	if resp.SessionID == 0 {
		ctest.Failedm("session id is zero")
		return nil
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	if resp.Challenge.ChallengeType != vsapi.CHALLENGE_TYPE_HMAC_SHA256 {
		ctest.Failedm(fmt.Sprintf("unexpected challenge type: expected %d, got %d",
			vsapi.CHALLENGE_TYPE_HMAC_SHA256,
			resp.Challenge.ChallengeType))
		return nil
	}
	if len(resp.Challenge.ChallengeData) < MinChallengeNonceSize {
		ctest.Failedm(fmt.Sprintf("challenge data is too short: expected at least %d bytes, got %d",
			MinChallengeNonceSize,
			len(resp.Challenge.ChallengeData)))
		return nil
	}
	zeroCount := 0
	for _, b := range resp.Challenge.ChallengeData {
		if b == 0 {
			zeroCount++
		}
	}
	if zeroCount == len(resp.Challenge.ChallengeData) {
		ctest.Failedm("challenge data is all zeros")
		return nil
	}
	ctest.Passed()
	return nil
}

// Send back a challenge response that is clearly not valid.
func RunRejectInvalidAuth(state *TestState, ctest *TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}

	// NODE->VS : Hello
	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	pause()

	// NODE->VS : Authenticate
	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  0,
		NodeCert:   nil,
		Hmac:       nil,
		VssService: "",
		NodeAgent:  nil,
	}
	apiKey, err := mockNode.Authenticate(&authReq)
	if err == nil {
		ctest.Failedm(fmt.Sprintf("authenticate succeeded with invalid auth: %s", apiKey))
		return nil
	}
	ctest.Passed()
	return nil
}

// Run a valid auth.
// TODO: Needs to kick off a VSS on the mock node.
//
// Note that node state will keep track of the API key.
func RunAcceptValidAuth(state *TestState, ctest *TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}

	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	pause()

	timestamp := time.Now().Unix()

	if state.policy == nil {
		err := loadPolicy(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		pause()
	}

	nodeCR := GetNodeConnect(state.policy)
	if nodeCR == nil {
		ctest.Failedm("no node connect information found in policy")
		return nil
	}

	nodeName := nodeCR.GetNodeName()
	if nodeName == "" {
		// This is a policy error.
		ctest.Failedm("node name not found node service list")
		return nil
	}

	nodeAgent, err := CreateNodeAgent(state.policy, 3600)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	m2HMAC := newM2HMAC(resp.Challenge.ChallengeData, resp.SessionID, timestamp)

	// NODE->VS : Authenticate
	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  timestamp,
		NodeCert:   certToPEM(state.nodeCert),
		Hmac:       m2HMAC,
		VssService: "127.0.0.1:31337", // HMM normally this would need to be a ZPR address
		NodeAgent:  nodeAgent,
	}
	state.log.Infow("attempting authenticate for node", "node_name", nodeName, "CN", nodeCR.CN)
	apiKey, err := mockNode.Authenticate(&authReq)
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if apiKey == "" {
		ctest.Failedm("authenticate failed to return an API key")
		return nil
	}
	ctest.Passed()
	return nil
}

func RunAuthorizeConnect(state *TestState, ctest *TestRun) error {
	// If we don't have an API key in state, run the accept-valid-auth test.
	node, err := state.GetNode()
	if err != nil {
		return err
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		pause()
	}
	if !node.HasApiKey() {
		ctest.Failedm("unable to get an API key from node")
		return nil
	}

	if state.policy == nil {
		err := loadPolicy(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		pause()
	}

	// Pick a non-node, non-provider to connect as.
	connects := GetConnects(state.policy)
	if connects == nil {
		ctest.Failedm("cannot find any authorized connectors in policy")
		return nil
	}

	var candidate *ConnectRec
	var nodeCR *ConnectRec
	for _, connect := range connects {
		if connect.IsNode() {
			if nodeCR != nil {
				panic("expecting only one node in policy")
			}
			nodeCR = connect
			continue
		}
		if len(connect.Provides) > 0 {
			continue
		}
		if candidate == nil {
			candidate = connect
		}
	}
	if nodeCR == nil {
		panic("expecting a node in policy")
	}
	if candidate == nil {
		ctest.Failedm("cannot find any non-node, non-provider in policy")
		return nil
	}

	agent, err := connectAdapter(node, candidate, nodeCR.Addr, state.GetNextOctect())
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// TODO: Check the agent.
	if agent == nil {
		ctest.Failedm("authorize-connect did not return an agent")
		return nil
	}

	ctest.Passed()
	return nil
}

// Connect node, then a client and a service and send in a visa request which should then be granted.
func RunVisaRequest(state *TestState, ctest *TestRun) error {
	node, err := state.GetNode()
	if err != nil {
		return err
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		if !node.HasApiKey() {
			ctest.Failedm("unable to get an API key from node")
			return nil
		}
		pause()
	}

	if state.policy == nil {
		err := loadPolicy(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		pause()
	}

	// Pick a non-node, non-provider to connect as.
	connects := GetConnects(state.policy)
	if connects == nil {
		ctest.Failedm("cannot find any authorized connectors in policy")
		return nil
	}

	var candidate *ConnectRec
	var nodeCR *ConnectRec
	var service *ConnectRec
	for _, connect := range connects {
		if connect.IsNode() {
			if nodeCR != nil {
				panic("expecting only one node in policy")
			}
			nodeCR = connect
			continue
		}
		if connect.IsVisaService() {
			continue
		}
		if len(connect.Provides) > 0 {
			if service == nil {
				service = connect
				continue
			}
		} else if candidate == nil {
			candidate = connect
		}
	}
	if nodeCR == nil {
		panic("expecting a node in policy")
	}
	if candidate == nil {
		ctest.Failedm("cannot find any non-node, non-provider in policy")
		return nil
	}
	if service == nil {
		ctest.Failedm("cannot find a suitable service for visa request testing")
		return nil
	}

	// TODO: Figure out what attributes our client needs in order to talk to service.
	//       Then ensure those attributes are present.

	// Connect the service:
	var svcID string
	for sid := range service.Provides {
		svcID = sid
		break
	}

	commPols := GetCommPoliciesForService(state.policy, svcID)
	if len(commPols) == 0 {
		ctest.Failedm(fmt.Sprintf("no communication policies found for service %s", svcID))
		return nil
	}
	commPol := commPols[0]

	// Right now this tool only knows how to make a TCP connect.
	endpoints := FilterTCPScope(commPol.Scope)
	if endpoints == nil {
		ctest.Failedm(fmt.Sprintf("cannot find TCP scope from communication policy for %v", svcID))
		return nil
	}
	commEndpoint := endpoints[0]

	state.log.Infow("connecting a service", "service_id", svcID)
	svcAgnt, err := connectAdapter(node, service, nodeCR.Addr, state.GetNextOctect())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect service: %w", err))
		return nil
	}
	pause()

	// Connect the client:
	state.log.Infow("connecting a client", "CN", candidate.CN)
	cliAgnt, err := connectAdapter(node, candidate, nodeCR.Addr, state.GetNextOctect())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect client: %w", err))
		return nil
	}
	pause()

	// Request a visa:
	sourceAddr, _ := netip.AddrFromSlice(cliAgnt.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(svcAgnt.ZprAddr)

	state.log.Infow("preparing visa request", "source", sourceAddr, "dest", destAddr, "comm_endpoint", commEndpoint)

	pkt, l3t, err := GeneratePacket(sourceAddr, destAddr, commEndpoint)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	vresp, err := node.RequestVisa(node.GetAPIKey(), sourceAddr, l3t, pkt)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	if vresp.Status != vsapi.StatusCode_SUCCESS {
		ctest.Failed(fmt.Errorf("visa request failed: %v", vresp.Reason))
		return nil
	}

	if vresp.Visa == nil {
		ctest.Failedm("visa service returns nil visa")
		return nil
	}

	if vresp.Visa.IssuerID <= 0 {
		ctest.Failedm(fmt.Sprintf("visa service returns invalid issuer id: %d", vresp.Visa.IssuerID))
		return nil
	}

	// TODO: check other visa aspects.
	ctest.Passed()
	return nil
}

func connectAdapter(node *mocks.Node, crec *ConnectRec, dockAddr netip.Addr, octect uint32) (*vsapi.Agent, error) {
	claims := make(map[string]string)
	claims["zpr.adapter.cn"] = crec.CN
	if crec.HasAddr() {
		claims["zpr.addr"] = crec.Addr.String()
	} else {
		// Hmm, just make one up?
		claims["zpr.addr"] = fmt.Sprintf("fd5a:5052:1::%d", octect)
	}

	cid := rand.Int31()
	creq := vsapi.ConnectRequest{
		ConnectionID:       cid,
		DockAddr:           dockAddr.AsSlice(),
		Claims:             claims,
		Challenge:          nil,
		ChallengeResponses: nil,
	}

	// NODE->VS : AuthorizeConnect
	cresp, err := node.AuthorizeConnect(node.GetAPIKey(), &creq)
	if err != nil {
		return nil, err
	}

	if cresp.ConnectionID != cid {
		return nil, fmt.Errorf("connection id mismatch: expected %d, got %d", cid, cresp.ConnectionID)
	}
	if cresp.Status != vsapi.StatusCode_SUCCESS {
		return nil, fmt.Errorf("status not success: %d (%s): %v", cresp.Status, cresp.Status, cresp.Reason)
	}

	// TODO: Check the agent.

	return cresp.Agent, nil
}

func connectNodeAndGetApiKey(state *TestState) (string, error) {
	mockNode, err := state.GetNode()
	if err != nil {
		return "", err
	}

	if state.policy == nil {
		if err := loadPolicy(state); err != nil {
			return "", err
		}
		pause()
	}

	resp, err := mockNode.Hello()
	if err != nil {
		return "", err
	}
	if resp.Challenge == nil {
		return "", fmt.Errorf("challenge from VS is nil")
	}
	timestamp := time.Now().Unix()
	nodeCR := GetNodeConnect(state.policy)
	if nodeCR == nil {
		return "", fmt.Errorf("no node connect information found in policy")
	}

	nodeName := nodeCR.GetNodeName()
	if nodeName == "" {
		// This is a policy error.
		return "", fmt.Errorf("node name not found node service list")
	}

	nodeAgent, err := CreateNodeAgent(state.policy, 3600)
	if err != nil {
		return "", err
	}

	m2HMAC := newM2HMAC(resp.Challenge.ChallengeData, resp.SessionID, timestamp)

	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  timestamp,
		NodeCert:   certToPEM(state.nodeCert),
		Hmac:       m2HMAC,
		VssService: "127.0.0.1:31337", // HMM normally this would need to be a ZPR address
		NodeAgent:  nodeAgent,
	}
	state.log.Infow("attempting authenticate for node", "node_name", nodeName, "CN", nodeCR.CN)
	apiKey, err := mockNode.Authenticate(&authReq)
	if err != nil {
		return "", err
	}
	if apiKey == "" {
		return "", fmt.Errorf("authenticate failed to return an API key")
	}
	return apiKey, nil
}

// sets state.policy if all goes well.
func loadPolicy(state *TestState) error {
	cli, err := state.GetAdminClient()
	if err != nil {
		return err
	}
	pol, err := cli.GetCurrentPolicy()
	if err != nil {
		return fmt.Errorf("failed to get current policy using admin interface: %v", err)
	}
	state.policy = pol
	state.log.Infow("policy extracted from container", "serial", pol.GetSerialVersion())
	return nil
}

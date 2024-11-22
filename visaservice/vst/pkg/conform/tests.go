package conform

import (
	"fmt"
	"time"

	"zpr.org/vst/pkg/vsapi"
)

const MinChallengeNonceSize = 32
const HelloRepsCount = 100

func RunTest(test ConformanceTest, state *TestState, card *Scorecard) error {
	runf, ok := runners[test]
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

// If this works, it stores the current policy in the state.
func RunGetCurrentPolicy(state *TestState, ctest *TestRun) error {
	cli, err := state.GetAdminClient()
	if err != nil {
		return err
	}
	pol, err := cli.GetCurrentPolicy()
	if err != nil {
		return fmt.Errorf("failed to get current policy using admin interface: %v", err)
	}
	ctest.Passed()
	state.policy = pol
	state.log.Infow("policy extracted from container", "serial", pol.GetSerialVersion())
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

	// NODE->VS : Hello
	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}

	nodeCR := GetNodeConnect(state.policy)
	if nodeCR == nil {
		ctest.Failedm("no node connect information found in policy")
		return nil
	}

	timestamp := time.Now().Unix()

	// What claims do I need -- these are in policy?
	claims := make(map[string]string)
	if nodeCR.CN != "" {
		claims["zpr.adapter.cn"] = nodeCR.CN
	}

	// These come from policy I believe
	nodeAddr := nodeCR.Addr
	tetherAddr := nodeAddr

	// Node name is last section of the provides path.
	nodeName := nodeCR.GetNodeName()
	if nodeName == "" {
		// This is a policy error.
		ctest.Failedm("node name not found node service list")
		return nil
	}

	var provides []string
	for sname := range nodeCR.Provides {
		provides = append(provides, sname)
	}

	nodeAgent := vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
		Attrs:       claims,
		AuthExpires: timestamp + 3600,
		ZprAddr:     nodeAddr.AsSlice(),    // zpr address
		TetherAddr:  tetherAddr.AsSlice(),  // tether address
		Ident:       "ident-not-generated", // identity
		Provides:    provides,              // []string
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
		NodeAgent:  &nodeAgent,
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

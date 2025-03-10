package tests

import (
	"time"

	"zpr.org/vsapi"
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vst/pkg/zcrypt"
)

type AcceptValidAuth struct{}

func init() {
	testfw.Register(&AcceptValidAuth{})
}

func (t *AcceptValidAuth) Name() string {
	return "AcceptValidAuth"
}

func (t *AcceptValidAuth) Order() int {
	return 200
}

// Run a valid auth.
//
// Note that node state will keep track of the API key.
func (t *AcceptValidAuth) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}

	mockNode.DeRegister("") // ignore error
	state.Pause()

	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	state.Pause()

	timestamp := time.Now().Unix()

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	nodeCR := plc.GetNodeConnect(policy)
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

	nodeAgent, err := plc.CreateNodeAgent(policy, 3600)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	m2HMAC := zcrypt.GenM2HMAC(resp.Challenge.ChallengeData, resp.SessionID, timestamp)

	// NODE->VS : Authenticate
	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  timestamp,
		NodeCert:   zcrypt.CertToPEM(state.NodeCert),
		Hmac:       m2HMAC,
		VssService: "", // HMM normally this would need to be a ZPR address
		NodeAgent:  nodeAgent,
	}
	state.Log.Infow("attempting authenticate for node", "node_name", nodeName, "CN", nodeCR.CN)
	apiKey, err := mockNode.Authenticate(&authReq)
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if apiKey == "" {
		ctest.Failedm("authenticate failed to return an API key")
		return nil
	}
	state.Pause()
	state.Log.Info("XXX checking for policy info message...")

	// We should also have a policy message
	pi := mockNode.PopPolicyInfo()
	if pi == nil {
		ctest.Failedm("did not get a policy info message over VSS")
		return nil
	}
	pi = mockNode.PopPolicyInfo()
	if pi != nil {
		ctest.Failedm("got >1 info message over VSS")
		return nil
	}

	// We should get a visa
	// TODO: Actually we should get two visas- one for NODE-VS and one for VSS-VS.
	//       But we won't get the vss visa unless we spoof the real node ZPR address.
	vsa := mockNode.PopVisa()
	if vsa == nil {
		ctest.Failedm("did not get a visa message over VSS")
		return nil
	}

	ctest.Passed()
	return nil
}

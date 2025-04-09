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

func (t *AcceptValidAuth) Order() testfw.Order {
	return testfw.OrderDontCare
}

// Run a valid auth.
//
// Note that node state will keep track of the API key.
func (t *AcceptValidAuth) Run(state *testfw.TestState) *testfw.RunResult {
	mockNode, err := state.GetNode()
	if err != nil {
		return testfw.Faile(err)
	}

	mockNode.DeRegister("") // ignore error
	state.Pause()

	resp, err := mockNode.Hello()
	if err != nil {
		return testfw.Faile(err)
	}
	if resp.Challenge == nil {
		return testfw.Fail("challenge is nil")
	}
	state.Pause()

	timestamp := time.Now().Unix()

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		return testfw.Faile(err)
	}

	nodeCR := plc.GetNodeConnect(policy)
	if nodeCR == nil {
		return testfw.Fail("no node connect information found in policy")
	}

	nodeName := nodeCR.GetNodeName()
	if nodeName == "" {
		// This is a policy error.
		return testfw.Fail("node name not found node service list")
	}

	nodeActor, err := plc.CreateNodeActor(policy, 3600)
	if err != nil {
		return testfw.Faile(err)
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
		NodeActor:  nodeActor,
	}
	state.Log.Infow("attempting authenticate for node", "node_name", nodeName, "CN", nodeCR.CN)
	apiKey, err := mockNode.Authenticate(&authReq)
	if err != nil {
		return testfw.Faile(err)
	}
	if apiKey == "" {
		return testfw.Fail("authenticate failed to return an API key")
	}
	state.Pause()

	// We should also have a policy message
	pi := mockNode.PopPolicyInfo()
	if pi == nil {
		return testfw.Fail("did not get a policy info message over VSS")
	}
	pi = mockNode.PopPolicyInfo()
	if pi != nil {
		return testfw.Fail("got >1 info message over VSS")
	}

	// We should get a visa
	// TODO: Actually we should get two visas- one for NODE-VS and one for VSS-VS.
	//       But we won't get the vss visa unless we spoof the real node ZPR address.
	vsa := mockNode.PopVisa()
	if vsa == nil {
		return testfw.Fail("did not get a visa message over VSS")
	}

	return testfw.Ok()
}

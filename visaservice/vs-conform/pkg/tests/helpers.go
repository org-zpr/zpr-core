package tests

import (
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vsapi"
	"zpr.org/vst/pkg/zcrypt"
)

func connectNodeAndGetApiKey(state *testfw.TestState) (string, error) {
	mockNode, err := state.GetNode()
	if err != nil {
		return "", err
	}

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		return "", err
	}

	resp, err := mockNode.Hello()
	if err != nil {
		return "", err
	}
	if resp.Challenge == nil {
		return "", fmt.Errorf("challenge from VS is nil")
	}
	timestamp := time.Now().Unix()
	nodeCR := plc.GetNodeConnect(policy)
	if nodeCR == nil {
		return "", fmt.Errorf("no node connect information found in policy")
	}

	nodeName := nodeCR.GetNodeName()
	if nodeName == "" {
		// This is a policy error.
		return "", fmt.Errorf("node name not found node service list")
	}

	nodeAgent, err := plc.CreateNodeAgent(policy, 3600)
	if err != nil {
		return "", err
	}

	m2HMAC := zcrypt.GenM2HMAC(resp.Challenge.ChallengeData, resp.SessionID, timestamp)

	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  timestamp,
		NodeCert:   zcrypt.CertToPEM(state.NodeCert),
		Hmac:       m2HMAC,
		VssService: "", // node code will set this
		NodeAgent:  nodeAgent,
	}
	state.Log.Infow("attempting authenticate for node", "node_name", nodeName, "CN", nodeCR.CN)
	apiKey, err := mockNode.Authenticate(&authReq)
	if err != nil {
		return "", err
	}
	if apiKey == "" {
		return "", fmt.Errorf("authenticate failed to return an API key")
	}
	return apiKey, nil
}

// Note that `zprAddr` is only used if the connect record from policy does not
// include the `zpr.addr` attribute.
func connectAdapter(node *mocks.Node, crec *plc.ConnectRec, dockAddr, zprAddr netip.Addr) (*vsapi.Agent, error) {
	claims := make(map[string]string)
	claims["zpr.adapter.cn"] = crec.CN
	if crec.HasAddr() {
		claims["zpr.addr"] = crec.Addr.String()
	} else {
		// Hmm, just make one up?
		claims["zpr.addr"] = zprAddr.String()
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

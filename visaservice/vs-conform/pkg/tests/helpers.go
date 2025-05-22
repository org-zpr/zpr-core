package tests

import (
	"fmt"
	"math/rand"
	"net/netip"
	"time"

	"zpr.org/vsapi"
	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vst/pkg/zcrypt"
	"zpr.org/vsx/polio"
)

type CommunicatingPair struct {
	CommPol      *polio.CPolicy
	CommEndpoint *polio.Scope
	DockAddr     netip.Addr
	Service      *plc.ConnectRec
	Client       *plc.ConnectRec
}

func findCommunicatingPair(policy *polio.Policy) (*CommunicatingPair, error) {
	// Pick a non-node, non-provider to connect as.
	connects := plc.GetConnects(policy)
	if connects == nil {
		return nil, fmt.Errorf("cannot find any authorized connectors in policy")
	}

	var candidate *plc.ConnectRec
	var nodeCR *plc.ConnectRec
	var service *plc.ConnectRec
	var svcEndpoint *polio.Scope
	var commPol *polio.CPolicy
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
		if !plc.ConnectRecHasSetAttr(connect, plc.KAttrCN) {
			// We cannot self-auth without this
			continue
		}
		if len(connect.Provides) > 0 {
			if service == nil {
				if ep, cpol := findTCPEndpoint(connect, policy); ep != nil {
					svcEndpoint = ep
					commPol = cpol
					service = connect
				}
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
		return nil, fmt.Errorf("cannot find any non-node, non-provider in policy")
	}
	if service == nil {
		return nil, fmt.Errorf("cannot find a suitable (TCP) service for visa request testing")
	}

	return &CommunicatingPair{
		CommPol:      commPol,
		CommEndpoint: svcEndpoint,
		DockAddr:     nodeCR.Addr,
		Service:      service,
		Client:       candidate,
	}, nil
}

func reconnectNode(state *testfw.TestState) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}
	if mockNode.HasApiKey() {
		state.Close()
	}
	_, err = connectNodeAndGetApiKey(state)
	return err
}

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

	nodeActor, err := plc.CreateNodeActor(policy, 3600)
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
		NodeActor:  nodeActor,
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
func connectAdapter(node *mocks.Node, crec *plc.ConnectRec, dockAddr, zprAddr netip.Addr) (*vsapi.Actor, error) {
	claims := make(map[string]string)
	claims[plc.KAttrCN] = crec.CN
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
		return nil, fmt.Errorf("status not success: %d (%s): %s", cresp.Status, cresp.Status, cresp.GetReason())
	}

	// TODO: Check the actor.

	return cresp.Actor, nil
}

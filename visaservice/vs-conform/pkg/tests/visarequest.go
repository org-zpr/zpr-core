package tests

import (
	"fmt"
	"net/netip"

	"zpr.org/vsapi"
	"zpr.org/vst/pkg/packets"
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vsx/polio"
)

type VisaRequest struct{}

func init() {
	// testfw.Register(&VisaRequest{})  // TODO: test needs to use bootstrap auth
}

func (t *VisaRequest) Name() string {
	return "VisaRequest"
}

func (t *VisaRequest) Order() testfw.Order {
	return testfw.OrderLater
}

// Connect node, then a client and a service and send in a visa request which should then be granted.
func (t *VisaRequest) Run(state *testfw.TestState) *testfw.RunResult {
	node, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			return testfw.Faile(err)
		}
		if !node.HasApiKey() {
			return testfw.Fail("unable to get an API key from node")
		}
		state.Pause()
	}

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		return testfw.Faile(err)
	}

	cpair, err := findCommunicatingPair(policy)
	if err != nil {
		return testfw.Faile(err)
	}

	// TODO: Figure out what attributes our client needs in order to talk to service.
	//       Then ensure those attributes are present.

	state.Log.Infow("connecting a service", "endpoint", cpair.CommEndpoint)
	svcAgnt, err := connectAdapter(node, cpair.Service, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		return testfw.Faile(fmt.Errorf("failed to connect service: %w", err))
	}
	state.Pause()

	// Connect the client:
	state.Log.Infow("connecting a client", "CN", cpair.Client.CN)
	cliAgnt, err := connectAdapter(node, cpair.Client, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		return testfw.Faile(fmt.Errorf("failed to connect client (CN='%v'): %w", cpair.Client.CN, err))
	}
	state.Pause()

	// Request a visa:
	sourceAddr, _ := netip.AddrFromSlice(cliAgnt.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(svcAgnt.ZprAddr)

	state.Log.Infow("preparing visa request", "source", sourceAddr, "dest", destAddr, "comm_endpoint", cpair.CommEndpoint)

	{
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, cpair.CommEndpoint)
		if err != nil {
			return testfw.Faile(err)
		}

		vresp, err := node.RequestVisa(node.GetAPIKey(), sourceAddr, l3t, pkt)
		if err != nil {
			return testfw.Faile(err)
		}

		if vresp.Status != vsapi.StatusCode_SUCCESS {
			return testfw.Faile(fmt.Errorf("visa request failed: %v", vresp.Reason))
		}

		if vresp.Visa == nil {
			return testfw.Fail("visa service returns nil visa")
		}

		if vresp.Visa.IssuerID <= 0 {
			return testfw.Failf("visa service returns invalid issuer id: %d", vresp.Visa.IssuerID)
		}
	}

	// Now generate a packet between the valid hosts but use incorrect port.
	{
		badEp := plc.GenEndpointNotInScope(packets.ProtocolTCP, cpair.CommPol.Scope)
		state.Log.Infow("preparing visa request with invalid port", "source", sourceAddr, "dest", destAddr, "comm_endpoint", badEp)
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, badEp)
		if err != nil {
			return testfw.Faile(err)
		}

		vresp, err := node.RequestVisa(node.GetAPIKey(), sourceAddr, l3t, pkt)
		if err != nil {
			return testfw.Faile(err)
		}

		if vresp.Status == vsapi.StatusCode_SUCCESS {
			return testfw.Faile(fmt.Errorf("visa request for invalid port succeeded"))
		}
	}

	// TODO: check other visa aspects.
	return testfw.Ok()
}

func findTCPEndpoint(service *plc.ConnectRec, policy *polio.Policy) (*polio.Scope, *polio.CPolicy) {
	// Connect the service:
	for sid := range service.Provides {
		commPols := plc.GetCommPoliciesForService(policy, sid)
		if len(commPols) == 0 {
			continue
		}
		commPol := commPols[0]
		endpoints := plc.FilterTCPScope(commPol.Scope)
		if endpoints == nil {
			continue
		}
		return endpoints[0], commPol
	}
	return nil, nil
}

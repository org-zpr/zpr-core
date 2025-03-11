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
	testfw.Register(&VisaRequest{})
}

func (t *VisaRequest) Name() string {
	return "VisaRequest"
}

func (t *VisaRequest) Order() int {
	return 1000
}

// Connect node, then a client and a service and send in a visa request which should then be granted.
func (t *VisaRequest) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
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
		state.Pause()
	}

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	cpair, err := findCommunicatingPair(policy)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// TODO: Figure out what attributes our client needs in order to talk to service.
	//       Then ensure those attributes are present.

	state.Log.Infow("connecting a service", "endpoint", cpair.CommEndpoint)
	svcAgnt, err := connectAdapter(node, cpair.Service, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect service: %w", err))
		return nil
	}
	state.Pause()

	// Connect the client:
	state.Log.Infow("connecting a client", "CN", cpair.Client.CN)
	cliAgnt, err := connectAdapter(node, cpair.Client, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect client (CN='%v'): %w", cpair.Client.CN, err))
		return nil
	}
	state.Pause()

	// Request a visa:
	sourceAddr, _ := netip.AddrFromSlice(cliAgnt.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(svcAgnt.ZprAddr)

	state.Log.Infow("preparing visa request", "source", sourceAddr, "dest", destAddr, "comm_endpoint", cpair.CommEndpoint)

	{
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, cpair.CommEndpoint)
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
	}

	// Now generate a packet between the valid hosts but use incorrect port.
	{
		badEp := plc.GenEndpointNotInScope(packets.ProtocolTCP, cpair.CommPol.Scope)
		state.Log.Infow("preparing visa request with invalid port", "source", sourceAddr, "dest", destAddr, "comm_endpoint", badEp)
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, badEp)
		if err != nil {
			ctest.Failed(err)
			return nil
		}

		vresp, err := node.RequestVisa(node.GetAPIKey(), sourceAddr, l3t, pkt)
		if err != nil {
			ctest.Failed(err)
			return nil
		}

		if vresp.Status == vsapi.StatusCode_SUCCESS {
			ctest.Failed(fmt.Errorf("visa request for invalid port succeeded"))
			return nil
		}
	}

	// TODO: check other visa aspects.
	ctest.Passed()
	return nil
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

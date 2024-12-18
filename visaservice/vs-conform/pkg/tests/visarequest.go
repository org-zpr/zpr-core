package tests

import (
	"fmt"
	"net/netip"

	"zpr.org/vst/pkg/packets"
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vst/pkg/vsapi"
)

type VisaRequest struct{}

func init() {
	testfw.Register(&VisaRequest{})
}

func (t *VisaRequest) Name() string {
	return "VisaRequest"
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

	// Pick a non-node, non-provider to connect as.
	connects := plc.GetConnects(policy)
	if connects == nil {
		ctest.Failedm("cannot find any authorized connectors in policy")
		return nil
	}

	var candidate *plc.ConnectRec
	var nodeCR *plc.ConnectRec
	var service *plc.ConnectRec
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

	commPols := plc.GetCommPoliciesForService(policy, svcID)
	if len(commPols) == 0 {
		ctest.Failedm(fmt.Sprintf("no communication policies found for service %s", svcID))
		return nil
	}
	commPol := commPols[0]

	// Right now this tool only knows how to make a TCP connect.
	endpoints := plc.FilterTCPScope(commPol.Scope)
	if endpoints == nil {
		ctest.Failedm(fmt.Sprintf("cannot find TCP scope from communication policy for %v", svcID))
		return nil
	}
	commEndpoint := endpoints[0]

	state.Log.Infow("connecting a service", "service_id", svcID)
	svcAgnt, err := connectAdapter(node, service, nodeCR.Addr, state.GetNextAdapterAddr())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect service: %w", err))
		return nil
	}
	state.Pause()

	// Connect the client:
	state.Log.Infow("connecting a client", "CN", candidate.CN)
	cliAgnt, err := connectAdapter(node, candidate, nodeCR.Addr, state.GetNextAdapterAddr())
	if err != nil {
		ctest.Failed(fmt.Errorf("failed to connect client: %w", err))
		return nil
	}
	state.Pause()

	// Request a visa:
	sourceAddr, _ := netip.AddrFromSlice(cliAgnt.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(svcAgnt.ZprAddr)

	state.Log.Infow("preparing visa request", "source", sourceAddr, "dest", destAddr, "comm_endpoint", commEndpoint)

	{
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, commEndpoint)
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
		badEp := plc.GenEndpointNotInScope(packets.ProtocolTCP, commPol.Scope)
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

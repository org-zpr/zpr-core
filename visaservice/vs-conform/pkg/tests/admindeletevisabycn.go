package tests

import (
	"fmt"
	"net/netip"

	"zpr.org/vsapi"
	"zpr.org/vst/pkg/packets"
	"zpr.org/vst/pkg/testfw"
	"zpr.org/vsx/polio"
)

type AdminDeleteVisasByCN struct{}

func init() {
	testfw.Register(&AdminDeleteVisasByCN{})
}

func (t *AdminDeleteVisasByCN) Name() string {
	return "AdminDeleteVisasByCN"
}

func (t *AdminDeleteVisasByCN) Order() int {
	return 100
}

func (t *AdminDeleteVisasByCN) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	// Connect/Reconnect the node
	if err := reconnectNode(state); err != nil {
		ctest.Failed(err)
		return nil
	}
	state.Pause()

	admin, err := state.GetAdminClient()
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// List hosts, just to test interface
	origActors, err := admin.ListActors()
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// Attempt a delete for a non-existent CN. Should return zero count, not an error
	if rr, err := admin.RevokeActor("foo.baz"); err == nil {
		if rr.Count != 0 {
			ctest.Failedm(fmt.Sprintf("expected zero count for non-existent CN, got %d", rr.Count))
			return nil
		}
	} else {
		ctest.Failedm(fmt.Sprintf("unexpected error returned when deleting non-existent CN: %v", err))
		return nil
	}

	node, err := state.GetNode()
	if err != nil {
		return fmt.Errorf("state failed to return node: %w", err)
	}

	// Use policy to find a service and an adapter we can use to try to get a visa
	// for that service.  Similar here to the test for visa request.

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

	// Ensure that the actor is not already known to the visa service.
	for _, actor := range origActors {
		if actor.Cn == cpair.Client.CN {
			ctest.Failedm(fmt.Sprintf("actor already present in the visa service: %v", actor.Cn))
			return nil
		}
	}

	// Connect the service:
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

	// Check that we have a new CN in the visa service
	newActors, err := admin.ListActors()
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if len(newActors) <= len(origActors) {
		ctest.Failedm(fmt.Sprintf("expected more actors after connect, got %d", len(newActors)))
		return nil
	}

	// Request a visa:
	vresp, err := requestVisa(cliAgnt, svcAgnt, cpair.CommEndpoint, state)
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if vresp.Status != vsapi.StatusCode_SUCCESS {
		ctest.Failed(fmt.Errorf("visa request failed: %v", vresp.Reason))
		return nil
	}
	state.Pause()

	// At this point we should have an adapter connected with a known CN,
	// and at least one visa associated with that CN.

	origVisas, err := admin.ListVisas()
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	matched := 0
	for _, vdesc := range origVisas {
		if vdesc.VisaId == uint64(vresp.Visa.IssuerID) {
			matched++
		}
	}
	if matched < 1 {
		ctest.Failedm(fmt.Sprintf("visa %d not returned in visa list call", vresp.Visa.IssuerID))
		return nil
	}

	rr, err := admin.RevokeActor(cpair.Client.CN)
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if rr.Revoked != cpair.Client.CN {
		ctest.Failedm(fmt.Sprintf("expected CN %s in response, got %s", cpair.Client.CN, rr.Revoked))
		return nil
	}
	if rr.Count != uint32(matched) {
		ctest.Failedm(fmt.Sprintf("expected to remove %d visas, got %d", matched, rr.Count))
		return nil
	}

	ctest.Passed()
	return nil
}

func requestVisa(sourceAgent, destAgent *vsapi.Agent, commEndpoint *polio.Scope, state *testfw.TestState) (*vsapi.VisaResponse, error) {
	node, err := state.GetNode()
	if err != nil {
		return nil, err
	}
	sourceAddr, _ := netip.AddrFromSlice(sourceAgent.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(destAgent.ZprAddr)
	state.Log.Infow("preparing visa request", "source", sourceAddr, "dest", destAddr, "comm_endpoint", commEndpoint)
	var vresp *vsapi.VisaResponse
	{
		pkt, l3t, err := packets.GeneratePacket(sourceAddr, destAddr, commEndpoint)
		if err != nil {
			return nil, err
		}
		vresp, err = node.RequestVisa(node.GetAPIKey(), sourceAddr, l3t, pkt)
		if err != nil {
			return nil, err
		}
	}
	return vresp, nil
}

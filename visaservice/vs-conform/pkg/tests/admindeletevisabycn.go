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
	// testfw.Register(&AdminDeleteVisasByCN{}) // TODO: need to use bootstrap auth
}

func (t *AdminDeleteVisasByCN) Name() string {
	return "AdminDeleteVisasByCN"
}

func (t *AdminDeleteVisasByCN) Order() testfw.Order {
	return testfw.OrderLater
}

func (t *AdminDeleteVisasByCN) Run(state *testfw.TestState) *testfw.RunResult {
	// Connect/Reconnect the node
	if err := reconnectNode(state); err != nil {
		return testfw.Faile(err)
	}
	state.Pause()

	admin, err := state.GetAdminClient()
	if err != nil {
		return testfw.Faile(err)
	}

	// List hosts, just to test interface
	origActors, err := admin.ListActors()
	if err != nil {
		return testfw.Faile(err)
	}

	// Attempt a delete for a non-existent CN. Should return zero count, not an error
	if rr, err := admin.RevokeActor("foo.baz"); err == nil {
		if rr.Count != 0 {
			return testfw.Failf("expected zero count for non-existent CN, got %d", rr.Count)
		}
	} else {
		return testfw.Failf("unexpected error returned when deleting non-existent CN: %v", err)

	}

	node, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(fmt.Errorf("state failed to return node: %w", err))
	}

	// Use policy to find a service and an adapter we can use to try to get a visa
	// for that service.  Similar here to the test for visa request.

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		return testfw.Faile(err)
	}
	cpair, err := findCommunicatingPair(policy)
	if err != nil {
		return testfw.Faile(err)
	}

	// Ensure that the actor is not already known to the visa service.
	for _, actor := range origActors {
		if actor.Cn == cpair.Client.CN {
			return testfw.Failf("actor already present in the visa service: %v", actor.Cn)
		}
	}

	// Connect the service:
	state.Log.Infow("connecting a service", "endpoint", cpair.CommEndpoint)
	svcAgnt, err := connectAdapter(node, cpair.Service, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		return testfw.Failf("failed to connect service: %w", err)
	}
	state.Pause()

	// Connect the client:
	state.Log.Infow("connecting a client", "CN", cpair.Client.CN)
	cliAgnt, err := connectAdapter(node, cpair.Client, cpair.DockAddr, state.GetNextAdapterAddr())
	if err != nil {
		return testfw.Failf("failed to connect client (CN='%v'): %w", cpair.Client.CN, err)
	}
	state.Pause()

	// Check that we have a new CN in the visa service
	newActors, err := admin.ListActors()
	if err != nil {
		return testfw.Faile(err)
	}
	if len(newActors) <= len(origActors) {
		return testfw.Failf("expected more actors after connect, got %d", len(newActors))
	}

	// Request a visa:
	vresp, err := requestVisa(cliAgnt, svcAgnt, cpair.CommEndpoint, state)
	if err != nil {
		return testfw.Faile(err)
	}
	if vresp.Status != vsapi.StatusCode_SUCCESS {
		return testfw.Failf("visa request failed: %v", vresp.Reason)
	}
	state.Pause()

	// At this point we should have an adapter connected with a known CN,
	// and at least one visa associated with that CN.

	origVisas, err := admin.ListVisas()
	if err != nil {
		return testfw.Faile(err)
	}
	matched := 0
	for _, vdesc := range origVisas {
		if vdesc.VisaId == uint64(vresp.Visa.IssuerID) {
			matched++
		}
	}
	if matched < 1 {
		return testfw.Failf("visa %d not returned in visa list call", vresp.Visa.IssuerID)
	}

	rr, err := admin.RevokeActor(cpair.Client.CN)
	if err != nil {
		return testfw.Faile(err)
	}
	if rr.Revoked != cpair.Client.CN {
		return testfw.Failf("expected CN %s in response, got %s", cpair.Client.CN, rr.Revoked)
	}
	if rr.Count != uint32(matched) {
		return testfw.Failf("expected to remove %d visas, got %d", matched, rr.Count)
	}

	return testfw.Ok()
}

func requestVisa(sourceActor, destActor *vsapi.Actor, commEndpoint *polio.Scope, state *testfw.TestState) (*vsapi.VisaResponse, error) {
	node, err := state.GetNode()
	if err != nil {
		return nil, err
	}
	sourceAddr, _ := netip.AddrFromSlice(sourceActor.ZprAddr)
	destAddr, _ := netip.AddrFromSlice(destActor.ZprAddr)
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

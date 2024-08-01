package vservice

import (
	"fmt"
	"net/netip"

	"golang.org/x/net/context"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vs/pkg/vservice/adb"
	"zpr.org/vs/pkg/vssapi"
)

// Called by InstallPolicy
func (vs *VSInst) installPolicyWithVisasForNodes(pp *policy.Policy, configID uint64) error {
	errCount := 0
	for _, nodeAddr := range vs.agentDB.GetNodeList() {
		if err := vs.installPolicyWithVisasForNode(nodeAddr, pp, configID); err != nil {
			vs.log.WithError(err).Warn("failed to install policy on node", "node", nodeAddr)
			errCount++
		}
	}
	if errCount > 0 {
		return fmt.Errorf("failed to install policy on %d nodes", errCount)
	}
	return nil
}

func (vs *VSInst) installPolicyWithVisasForNode(nodeAddr netip.Addr, pp *policy.Policy, configID uint64) error {
	var visas []*vssapi.VisaHop
	var vssPort uint16

	serviceAddr := vs.agentDB.GetNodeVSSAddr(nodeAddr)
	if serviceAddr == "" {
		return fmt.Errorf("no support service addr for node")
	}
	if ap, err := netip.ParseAddrPort(serviceAddr); err == nil {
		vssPort = ap.Port()
		if vssPort == 0 {
			// Problem!
			return fmt.Errorf("misconfiguration - VSS reported port is zero (service_address = %v)", serviceAddr)
		}
		// The node tells the visa service its service address for the VSS. We assume that
		// the address part matches the node address. That may not always be true but we
		// confirm that here with an error message.
		if ap.Addr() != nodeAddr {
			vs.log.Error("node address does not match VSS address: VS->VSS visa will fail", "node", nodeAddr, "service_addr", serviceAddr)
		}
	} else {
		return fmt.Errorf("invalid serice address for VSS: %v", serviceAddr)
	}

	{

		vs.log.Info("generating a new visa-service visa for the node->VS", "node_addr_src", nodeAddr, "vs_addr_dest", vs.localAddr)
		pktData := snip.NewTCPConnect(nodeAddr, 0, vs.localAddr, VisaServicePort)
		vs.log.Debug("invoking request-visa for part of policy install (1/2)", "for_node", nodeAddr)
		vsr, err := vs.doRequestVisa(context.Background(), nodeAddr, pktData, 0, pp.VersionNumber())
		if err != nil {
			vs.log.WithError(err).Warn("failed to generate a visa-service visa for the node", "node_addr", nodeAddr)
		} else if vsr.Status != vsapi.StatusCode_SUCCESS {
			vs.log.Warn("failed to generate a visa-service visa for the node", "node", nodeAddr, "reason", vsr.Reason)
		} else {
			visas = append(visas, &vssapi.VisaHop{
				VisaPb:   vsr.Visa.VisaPb,
				HopCount: vsr.Visa.HopCount,
				IssuerID: vsr.Visa.IssuerID,
			})
		}
	}
	{
		vs.log.Info("generating a new visa-support-service visa for the VS->node", "vs_addr_src", vs.localAddr, "node_addr_dest", nodeAddr)
		pktData := snip.NewTCPConnect(vs.localAddr, 0, nodeAddr, vssPort)
		vs.log.Debug("invoking request-visa for part of policy install (2/2)", "for_node", nodeAddr)
		vsr, err := vs.doRequestVisa(context.Background(), vs.localAddr, pktData, 0, pp.VersionNumber())
		if err != nil {
			vs.log.WithError(err).Warn("failed to generate a visa-service visa for the node")
		} else if vsr.Status != vsapi.StatusCode_SUCCESS {
			vs.log.Warn("failed to generate a visa-support-service visa for the node", "reason", vsr.Reason)
		} else {
			visas = append(visas, &vssapi.VisaHop{
				VisaPb:   vsr.Visa.VisaPb,
				HopCount: vsr.Visa.HopCount,
				IssuerID: vsr.Visa.IssuerID,
			})
		}
	}

	if err := vs.updateNode(nodeAddr, pp.VersionNumber(), configID, visas); err != nil {
		// Failed to update, stuff them in the push buffer.
		vs.log.WithError(err).Warn("failed to update node during a policy install -- buffering", "node", nodeAddr)
		item := adb.PushItem{
			NodeAddr: nodeAddr,
			Visas:    visas,
		}
		vs.agentDB.BufferItemsForNode(nodeAddr, []*adb.PushItem{&item})
		return err
	}
	return nil
}

// For update node to work, we need to push the policy and version, plus all the visas.
// This updates the WantXXX values in the peer record state.
// If it completes, we update the LastXXX values in the peer record too.
//
// This does not use the push-buffer.
func (vs *VSInst) updateNode(nodeAddr netip.Addr, policyVer uint64, configID uint64, visas []*vssapi.VisaHop) error {
	var serviceAddr string
	var opErr error

	// if updating false, set true.

	oldValue, ok := vs.agentDB.TestAndSetUpdating(nodeAddr, false, true)
	if !ok {
		return fmt.Errorf("node not found")
	}
	if oldValue {
		// already updating
		return nil
	}
	serviceAddr = vs.agentDB.GetNodeVSSAddr(nodeAddr)
	if serviceAddr == "" {
		return fmt.Errorf("no VSS address for node")
	}
	if ok := vs.agentDB.SetPeerDesiredPolicyState(nodeAddr, policyVer, configID); !ok {
		return fmt.Errorf("node not found")
	}

	client := NewVSSCli(serviceAddr)

	if err := client.SendNetworkPolicy(policyVer, configID); err != nil {
		opErr = fmt.Errorf("failed to send network policy message to node: %w", err)
		goto RELEASE_UPDATE
	}

	if len(visas) > 0 {
		if err := client.SendVisas(visas); err != nil {
			opErr = fmt.Errorf("failed to send visas to node: %w", err)
			goto RELEASE_UPDATE
		}
	}

	// Success!
	_ = vs.agentDB.SetPeerLastPolicyState(nodeAddr, policyVer, configID)

RELEASE_UPDATE:
	_, _ = vs.agentDB.TestAndSetUpdating(nodeAddr, true, false)
	return opErr
}

func (vs *VSInst) EnqueuePushVisasToNode(addr netip.Addr, visas []*vssapi.VisaHop) {
	item := &adb.PushItem{
		NodeAddr: addr,
		Visas:    visas,
	}
	vs.visaPushC <- item
}

// This is the actual push function that is called in our little run-loop.
// Do not call this directly -- use PushVisa.
//
// We use the VSS to send the item and if send fails we put the item on the
// node buffer (in agentDB) for retry.
func (vs *VSInst) pushToNode(item *adb.PushItem) {
	if item.Broadcast {
		// Push to all nodes!
		for _, node := range vs.agentDB.GetNodeList() {
			vs.pushToNodeOrBuffer(node, []*adb.PushItem{item})
		}
	} else {
		vs.pushToNodeOrBuffer(item.NodeAddr, []*adb.PushItem{item})
	}
}

func (vs *VSInst) pushToNodeOrBuffer(nodeAddr netip.Addr, items []*adb.PushItem) {
	// We used to use a polling interface. Now we can use the VSS to send
	// directly to the node.

	vs.log.Debug("begin push items to node", "node", nodeAddr, "count", len(items))

	serviceAddr := vs.agentDB.GetNodeVSSAddr(nodeAddr)
	if serviceAddr == "" {
		vs.log.Warn("attempt to push to node but node not found", "addr", nodeAddr)
		return
	}

	client := NewVSSCli(serviceAddr)
	failing := adb.PushItem{}

	var revocations []*vssapi.VisaRevocation
	var visas []*vssapi.VisaHop
	for _, itm := range items {
		revocations = append(revocations, itm.Revocations...)
		visas = append(visas, itm.Visas...)
	}

	if len(revocations) > 0 {
		if err := client.SendRevocations(revocations); err != nil {
			failing.Revocations = append(failing.Revocations, revocations...)
			vs.log.WithError(err).Warn("failed to send revocations to node", "node", nodeAddr)
		}
	}

	if len(visas) > 0 {
		if err := client.SendVisas(visas); err != nil {
			failing.Visas = append(failing.Visas, visas...)
			vs.log.WithError(err).Warn("failed to send visas to node", "node", nodeAddr)
		}
	}

	if len(failing.Revocations) > 0 || len(failing.Visas) > 0 {
		vs.log.Debug("adding visas/revocations to pushbuffer for node", "node", nodeAddr, "visas", len(failing.Visas), "revocations", len(failing.Revocations))
		vs.agentDB.BufferItemsForNode(nodeAddr, []*adb.PushItem{&failing})
	}
}

func (vs *VSInst) handleNodeRegister(nodeAddr netip.Addr) {
	vs.log.Info("node registered", "nodeAddr", nodeAddr)
	// Now try to bring node into sycn-
	pp, _, configID := vs.getPolicyMatcherConfig()
	if err := vs.installPolicyWithVisasForNode(nodeAddr, pp, configID); err != nil {
		vs.log.WithError(err).Warn("failed to install initial policy on node", "node", nodeAddr)
	}
}

// checkNodeVSSState checks the VSS state of all nodes and sends config and policy to nodes
// which indicate they are out of sync.
//
// This should not be called by multiple routines at once.
func (vs *VSInst) checkNodesVSSState() {
	pp, _, configID := vs.getPolicyMatcherConfig()
	for _, nodeAddr := range vs.agentDB.GetOutOfSyncNonUpdatingNodes() {
		vs.log.Debug("checkNodesVSSState - node out of sync", "node", nodeAddr)
		if err := vs.installPolicyWithVisasForNode(nodeAddr, pp, configID); err != nil {
			vs.log.WithError(err).Warn("failed to install policy on node", "node", nodeAddr)
		}
	}
}

func (vs *VSInst) checkPushBuffers() {
	for _, nodeAddr := range vs.agentDB.GetNodesWithPending() {
		pushBuffer := vs.agentDB.DrainPending(nodeAddr)
		if len(pushBuffer) > 0 {
			vs.log.Debug("checkPushBuffers - found pending items for node", "node", nodeAddr, "count", len(pushBuffer))
			vs.pushToNodeOrBuffer(nodeAddr, pushBuffer)
		}
	}
}

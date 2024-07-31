package vservice

import (
	"fmt"
	"net/netip"

	"golang.org/x/net/context"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vs/pkg/vssapi"
)

// Called by InstallPolicy
func (vs *VSInst) installPolicyWithVisasForNodes(pp *policy.Policy, configID uint64) error {
	errCount := 0
	for _, nodeAddr := range vs.GetNodeList() {
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

	serviceAddr := vs.GetVSSAddrForNode(nodeAddr)
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
			vs.log.Warn("failed to generate a visa-service visa for the node", "reason", vsr.Reason)
		} else {
			visas = append(visas, &vssapi.VisaHop{
				VisaPb:   vsr.Visa.VisaPb,
				HopCount: vsr.Visa.HopCount,
				IssuerID: vsr.Visa.IssuerID,
			})
		}
	}

	return vs.updateNode(nodeAddr, pp.VersionNumber(), configID, visas)
}

// For update node to work, we need to push the policy and version, plus all the visas.
// This updates the WantXXX values in the peer record state.
// If it completes, we update the LastXXX values in the peer record too.
//
// This does not use the push-buffer.
func (vs *VSInst) updateNode(nodeAddr netip.Addr, policyVer uint64, configID uint64, visas []*vssapi.VisaHop) error {

	found := false
	updating := false
	var serviceAddr string
	var opErr error

	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			found = true
			if rec.Peer.State.Updating {
				updating = true
			} else {
				rec.Peer.State.WantPolicyVer = policyVer
				rec.Peer.State.WantConfigID = configID
				serviceAddr = rec.Peer.VSSAddr
				if serviceAddr != "" {
					rec.Peer.State.Updating = true // essentially takes a lock here
				}
			}
		}
	}
	vs.agentDB.Unlock()
	if updating {
		return nil
	}
	if !found {
		return fmt.Errorf("node not found")
	}
	if serviceAddr == "" {
		return fmt.Errorf("no VSS address for node")
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
	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			rec.Peer.State.LastPushConfigID = configID
			rec.Peer.State.LastPushPolicyVer = policyVer
		}
	}
	vs.agentDB.Unlock()

RELEASE_UPDATE:
	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			rec.Peer.State.Updating = false
		}
	}
	vs.agentDB.Unlock()
	return opErr
}

func (vs *VSInst) GetVSSAddrForNode(naddr netip.Addr) string {
	vs.agentDB.RLock()
	defer vs.agentDB.RUnlock()
	if rec, ok := vs.agentDB.agents[naddr]; ok {
		if rec.Peer != nil {
			return rec.Peer.VSSAddr
		}
	}
	return ""
}

func (vs *VSInst) EnqueuePushVisa(forNode netip.Addr, visas []*vssapi.VisaHop) {
	item := &PushItem{
		NodeAddr: forNode,
		Visas:    visas,
	}
	vs.visaPushC <- item
}

func (vs *VSInst) EnqueuePushVsapiVisas(visas []*vssapi.VisaHop) {
	item := &PushItem{
		Broadcast: true,
		Visas:     visas,
	}
	vs.visaPushC <- item
}

func (vs *VSInst) EnqueuePushVisaToAllNodes(visas []*vssapi.VisaHop) {
	item := &PushItem{
		Broadcast: true,
		Visas:     visas,
	}
	vs.visaPushC <- item
}

// This is the actual push function that is called in our little run-loop.
// Do not call this directly -- use PushVisa.
//
// We use the VSS to send the item and if send fails we put the item on the
// node buffer (in agentDB) for retry.
func (vs *VSInst) pushToNode(item *PushItem) {
	if item.Broadcast {
		// Push to all nodes!
		var nodes []netip.Addr
		vs.agentDB.RLock()
		for _, rec := range vs.agentDB.agents {
			if rec.Peer != nil {
				nodes = append(nodes, rec.ZPRAddr)
			}
		}
		vs.agentDB.RUnlock()
		for _, node := range nodes {
			vs.pushToNodeOrBuffer(node, item)
		}
	} else {
		vs.pushToNodeOrBuffer(item.NodeAddr, item)
	}
}

func (vs *VSInst) pushToNodeOrBuffer(nodeAddr netip.Addr, item *PushItem) {
	// We used to use a polling interface. Now we can use the VSS to send
	// directly to the node.

	vs.log.Debug("begin push items to node", "node", nodeAddr, "visa_count", len(item.Visas), "revocation_count", len(item.Revocations))

	var serviceAddr string
	vs.agentDB.RLock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			serviceAddr = rec.Peer.VSSAddr
		}
	}
	vs.agentDB.RUnlock()
	if serviceAddr == "" {
		vs.log.Warn("attempt to push to node but node not found", "addr", nodeAddr)
		return
	}

	client := NewVSSCli(serviceAddr)
	failing := PushItem{}

	if len(item.Revocations) > 0 {
		if err := client.SendRevocations(item.Revocations); err != nil {
			failing.Revocations = append(failing.Revocations, item.Revocations...)
			vs.log.WithError(err).Warn("failed to send revocations to node", "node", nodeAddr)
		}
	}

	if len(item.Visas) > 0 {
		if err := client.SendVisas(item.Visas); err != nil {
			failing.Visas = append(failing.Visas, item.Visas...)
			vs.log.WithError(err).Warn("failed to send visas to node", "node", nodeAddr)
		}
	}

	if len(failing.Revocations) > 0 || len(failing.Visas) > 0 {
		vs.agentDB.Lock()
		if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
			rec.Peer.PushBuffer = append(rec.Peer.PushBuffer, &failing)
		}
		vs.agentDB.Unlock()
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
func (vs *VSInst) checkNodesVSSState() {
	pp, _, configID := vs.getPolicyMatcherConfig()

	var nodes []netip.Addr
	vs.agentDB.RLock()
	for nodeAddr, rec := range vs.agentDB.agents {
		if rec.Peer == nil {
			continue
		}
		if rec.Peer.State.Updating {
			continue
		}
		if !rec.Peer.IsInSync() {
			nodes = append(nodes, nodeAddr)
		}
	}
	vs.agentDB.RUnlock()

	for _, nodeAddr := range nodes {
		vs.installPolicyWithVisasForNode(nodeAddr, pp, configID)
	}
}

func (vs *VSInst) checkPushBuffers() {
	var nodes []netip.Addr
	vs.agentDB.RLock()
	for nodeAddr, rec := range vs.agentDB.agents {
		if rec.Peer != nil && len(rec.Peer.PushBuffer) > 0 {
			nodes = append(nodes, nodeAddr)
		}
	}
	vs.agentDB.RUnlock()

	for _, nodeAddr := range nodes {
		// take the push buffer.
		var pushBuffer []*PushItem
		vs.agentDB.Lock()
		if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
			if rec.Peer != nil {
				pushBuffer = rec.Peer.PushBuffer
				rec.Peer.PushBuffer = nil
			}
		}
		vs.agentDB.Unlock()
		if len(pushBuffer) > 0 {
			var consolidated PushItem
			for _, item := range pushBuffer {
				consolidated.Visas = append(consolidated.Visas, item.Visas...)
				consolidated.Revocations = append(consolidated.Revocations, item.Revocations...)
			}
			vs.pushToNodeOrBuffer(nodeAddr, &consolidated)
		}
	}
}

package vservice

import (
	"net/netip"

	"zpr.org/vs/pkg/vsapi"
)

// Send the config-and-policy message over the VSS to the indicated node.
// Updates state in the agentDB.
func (vs *VSInst) SendConfigAndPolicyToNode(nodeAddr netip.Addr) {
	var serviceAddr string
	var vssPrevState VSSStateT

	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			serviceAddr = rec.Peer.VSSAddr
			vssPrevState = rec.Peer.VSSState
			if serviceAddr != "" {
				if vssPrevState == VSSStateUninitialized {
					rec.Peer.VSSState = VSSStateInitializing
				}
			}
		}
	}
	vs.agentDB.Unlock()

	if serviceAddr == "" {
		vs.log.Warn("node registered but VSS service address not in agentDB", "nodeAddr", nodeAddr)
		return
	}

	if vssPrevState != VSSStateUninitialized {
		// nothing to do
		return
	}

	var vssNextState VSSStateT
	plcy, _, cid := vs.getPolicyMatcherConfig()
	client := NewVSSCli(serviceAddr)
	if err := client.SendNetworkPolicy(plcy.VersionNumber(), cid); err != nil {
		vs.log.WithError(err).Error("failed to send network policy message to node", "service_addr", serviceAddr)
		vssNextState = VSSStateUninitialized
	} else {
		vssNextState = VSSStateInitialized
	}

	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
		if rec.Peer != nil {
			rec.Peer.VSSState = vssNextState
		}
	}
	vs.agentDB.Unlock()
}

func (vs *VSInst) PushVisa(forNode netip.Addr, visas []*vsapi.VisaHop) {
	item := &PushItem{
		NodeAddr: forNode,
		Item: &vsapi.PollResponse{
			Visas: visas,
		},
	}
	vs.visaPushC <- item
}

func (vs *VSInst) PushVisaToAllNodes(visas []*vsapi.VisaHop) {
	item := &PushItem{
		Broadcast: true,
		Item: &vsapi.PollResponse{
			Visas: visas,
		},
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
			vs.pushToNodeOrBuffer(node, item.Item)
		}
	} else {
		vs.pushToNodeOrBuffer(item.NodeAddr, item.Item)
	}
}

func (vs *VSInst) pushToNodeOrBuffer(nodeAddr netip.Addr, item *vsapi.PollResponse) {
	// We used to use a polling interface. Now we can use the VSS to send
	// directly to the node.

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
	failing := vsapi.PollResponse{}

	for _, rev := range item.Revocations {
		if err := client.SendRevocation(uint64(rev.Configuration), uint32(rev.IssuerID)); err != nil {
			failing.Revocations = append(failing.Revocations, rev)
			vs.log.WithError(err).Warn("failed to send revocation to node", "node", nodeAddr, "issuerID", rev.IssuerID)
		}
	}

	for _, visa := range item.Visas {
		if err := client.SendVisa(uint32(visa.IssuerID), visa.VisaPb, uint32(visa.HopCount)); err != nil {
			failing.Visas = append(failing.Visas, visa)
			vs.log.WithError(err).Warn("failed to send visa to node", "node", nodeAddr, "issuerID", visa.IssuerID)
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
	vs.SendConfigAndPolicyToNode(nodeAddr)
}

// checkNodeVSSState checks the VSS state of all nodes and sends config and policy to nodes
// which indicate they are uninitialized.
func (vs *VSInst) checkNodesVSSState() {
	var nodes []netip.Addr
	vs.agentDB.RLock()
	for nodeAddr, rec := range vs.agentDB.agents {
		if rec.Peer == nil {
			continue
		}
		if rec.Peer.VSSState == VSSStateUninitialized {
			nodes = append(nodes, nodeAddr)
		}
	}
	vs.agentDB.RUnlock()

	for _, nodeAddr := range nodes {
		vs.SendConfigAndPolicyToNode(nodeAddr)
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
		var pushBuffer []*vsapi.PollResponse
		vs.agentDB.Lock()
		if rec, ok := vs.agentDB.agents[nodeAddr]; ok {
			if rec.Peer != nil {
				pushBuffer = rec.Peer.PushBuffer
				rec.Peer.PushBuffer = nil
			}
		}
		vs.agentDB.Unlock()
		if len(pushBuffer) > 0 {
			for _, item := range pushBuffer {
				vs.pushToNodeOrBuffer(nodeAddr, item)
			}
		}
	}
}

package vservice

import (
	"net/netip"
	"time"

	"zpr.org/vs/pkg/agent"
)

// TODO: In prototype nodes call this. In new world order, the visa service does not
//       need any external call to this.  A node is added after a connect authorization.

// AddNode inform the visa service that a node has joined the ZPR. The node is then added
// to the list of expected "pollers" for visa service push messages.
//
// For now using the "register" call for this.
func (vs *VSInst) AddNode(addr netip.Addr, nodeAgent *agent.Agent) {
	vs.agentDB.Lock()
	vs.agentDB.agents[addr] = &HostRecord{
		CTime:      time.Now(),
		Agent:      nodeAgent,
		ZPRAddr:    addr,
		TetherAddr: addr,
	}
	vs.agentDB.Unlock()

	// minor race condition here:
	id := addr.String()
	if !vs.mb.HasPoller(id) {
		vs.mb.AddPoller(id)
	}
}

// RemoveNode removes the node at address 'addr' from the pollers list.
func (vs *VSInst) RemoveNode(addr netip.Addr) {
	vs.agentDB.Lock()

	if rec, ok := vs.agentDB.agents[addr]; !ok {
		vs.log.Warn("attempt to remove node but address not found", "addr", addr)
	} else {
		if rec.Agent.GetRole() != "node" {
			vs.log.Warn("attempt to remove node but record is not a node", "addr", addr, "type", rec.Agent.GetRole())
		} else {
			delete(vs.agentDB.agents, addr)
		}
	}
	vs.agentDB.Unlock()

	vs.mb.RemovePoller(addr.String())
}

func (vs *VSInst) RemoveAdapter(addr netip.Addr) {
	vs.agentDB.Lock()
	if rec, ok := vs.agentDB.agents[addr]; !ok {
		vs.log.Warn("attempt to remove adapter but address not found", "addr", addr)
	} else if rec.Agent.GetRole() != "adapter" {
		vs.log.Warn("attempt to remove adapter but record is not an adapter", "addr", addr, "type", rec.Agent.GetRole())
	} else {
		delete(vs.agentDB.agents, addr)
	}
	vs.agentDB.Unlock()
}

func (vs *VSInst) GetNodeList() []netip.Addr {
	vs.agentDB.RLock()
	defer vs.agentDB.RUnlock()

	var list []netip.Addr
	for addr := range vs.agentDB.agents {
		list = append(list, addr)
	}
	return list
}

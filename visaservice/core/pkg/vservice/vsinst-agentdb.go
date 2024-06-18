package vservice

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vsx/polio"
)

var (
	ErrorAgentExists = errors.New("agent already exists at address")
)

var (
	ErrorAgentExists = errors.New("agent already exists at address")
)

// AddNode inform the visa service that a node has joined the ZPR. The node is then added
// to the list of expected "pollers" for visa service push messages.
//
// For now using the "register" call for this.
func (vs *VSInst) AddNode(addr netip.Addr, nodeAgent *agent.Agent) error {
	vs.agentDB.Lock()

	if _, found := vs.agentDB.agents[addr]; found {
		vs.agentDB.Unlock()
		return ErrorAgentExists
	}

	vs.agentDB.agents[addr] = &HostRecord{
		CTime:      time.Now(),
		Agent:      nodeAgent,
		ZPRAddr:    addr,
		TetherAddr: addr, // ok?
	}
	vs.agentDB.Unlock()

	// minor race condition here:
	id := addr.String()
	if !vs.mb.HasPoller(id) {
		vs.mb.AddPoller(id)
	}
	vs.agentAdded(nodeAgent)
	return nil
}

func (vs *VSInst) AddAdapter(addr netip.Addr, agnt *agent.Agent) error {
	vs.agentDB.Lock()
	defer vs.agentDB.Unlock()

	if _, found := vs.agentDB.agents[addr]; found {
		return ErrorAgentExists
	}

	vs.agentDB.agents[addr] = &HostRecord{
		CTime:      time.Now(),
		Agent:      agnt,
		ZPRAddr:    addr,
		TetherAddr: agnt.GetTetherAddr(),
	}
	vs.agentAdded(agnt)
	return nil
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
			vs.agentRemoved(rec.Agent)
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
		vs.agentRemoved(rec.Agent)
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

func (vs *VSInst) AgentAtContactAddr(addr netip.Addr) (*agent.Agent, error) {
	vs.agentDB.RLock()
	defer vs.agentDB.RUnlock()

	rec, ok := vs.agentDB.agents[addr]
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	return rec.Agent, nil
}

func (vs *VSInst) agentAdded(agnt *agent.Agent) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()

	if curConfig != agnt.GetConfigID() {
		// Not sure yet if this is an issue, so will log it.
		vs.log.Warn("agent added with different config id", "agent_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}

	svcAddr, hasAddr := agnt.GetZPRID()
	if !hasAddr {
		return // no address, no service!
	}

	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				err := vs.authr.AddDatasourceProvider(serviceName, svcAddr, curConfig)
				if err != nil {
					vs.log.WithError(err).Error("failed to add auth service", "service_name", serviceName)
				} else {
					vs.log.Info("service added", "service", serviceName, "address", svcAddr)
				}
			}
		}
	}
}

func (vs *VSInst) agentRemoved(agnt *agent.Agent) {
	pp, _, curConfig := vs.getPolicyMatcherConfig()
	if curConfig != agnt.GetConfigID() {
		vs.log.Warn("host-remove with different configuration", "agent_config_id", agnt.GetConfigID(), "current_config", curConfig)
	}
	for _, serviceName := range agnt.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				if vs.authr.RemoveServiceByPrefix(psvc.GetPrefix()) > 0 {
					vs.log.Info("host_removed", "lost_service", serviceName)
				}
			}
		}
	}
}

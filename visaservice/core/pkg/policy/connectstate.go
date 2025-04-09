package policy

import (
	"errors"
	"fmt"
	"net/netip"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"

	"zpr.org/vsx/polio"
)

var (
	errUnknownFlag = errors.New("unknown flag")
	zeroAddr       = netip.Addr{}
)

// Configurator is that which can alter the global configuration.
type Configurator interface {
	SetConfig(key, value string) error
}

type Service struct {
	Name      string
	Type      polio.SvcT
	Endpoints []*snip.Endpoint
}

// ConnectState
//
// Implements vm.State
type ConnectState struct {
	Actor           *actor.Actor
	Node            bool                // TRUE if the NODE flag has been set
	Visaservice     bool                // TRUE if visa service flag has been set
	VisaserviceDock bool                // TURE if VS_DOCK has been set
	Services        map[string]*Service // name -> svc
	selfFlag        bool
	log             logr.Logger
	cfgr            Configurator // For altering global settings (is actually visa service)
}

// NewConnectState
//
// `edgeNode` is the endpoint for the node recieving the connect.
func NewConnectState(agnt *actor.Actor, cfgr Configurator, edgeNode netip.Addr, log logr.Logger) (*ConnectState, error) {
	remote, _ := agnt.GetZPRID()
	cs := &ConnectState{
		Actor:    agnt,
		Services: make(map[string]*Service),
		selfFlag: (remote != zeroAddr) && remote.String() == edgeNode.String(),
		log:      log,
		cfgr:     cfgr,
	}
	return cs, nil
}

// IsSelf implements vm.State.IsSelf
func (cs *ConnectState) IsSelf() bool {
	// TRUE if this state is for the invoking, local node.
	return cs.selfFlag
}

// SetConfig implements vm.State.SetConfig
func (cs *ConnectState) SetConfig(key, value string) error {
	// Global -- only invoke if acting on self.
	if !cs.selfFlag {
		cs.log.DPanic("attempt to set config on non-self flow state", "key", key, "value", value)
	}
	return cs.cfgr.SetConfig(key, value)
}

// RegisterService implements vm.State.RegisterService
func (cs *ConnectState) RegisterService(name string, stype polio.SvcT, endpoints []string) error {
	// endpoint form is: "tcp/80"
	var eps []*snip.Endpoint
	for _, s := range endpoints {
		if s == "" {
			continue
		}
		ep, err := snip.ParseEndpoint(s)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint for %v: `%v`: %v", name, s, err)
		}
		eps = append(eps, ep)
	}
	if len(eps) == 0 {
		// No endpoints? Not sure if this is correct behavior.
		cs.log.Info("service with no endpoints, ok for a node", "name", name)
	}
	cs.Services[name] = &Service{
		Name:      name,
		Type:      stype,
		Endpoints: eps,
	}
	return nil

}

// ConnectState implements vm.State.SetFlag
func (cs *ConnectState) SetFlag(ft polio.FlagT) error {
	switch ft {
	case polio.FlagT_F_NODE:
		cs.Node = true
	case polio.FlagT_F_VISASERVICE:
		cs.Visaservice = true
	case polio.FlagT_F_VS_DOCK:
		cs.VisaserviceDock = true
	default:
		return errUnknownFlag
	}
	if cs.Visaservice && cs.Node {
		return fmt.Errorf("policy error: both NODE and VISASERVICE flags set")
	}
	return nil
}

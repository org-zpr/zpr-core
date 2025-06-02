package plc

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"zpr.org/vsapi"
	"zpr.org/vst/pkg/packets"
	"zpr.org/vsx/polio"
)

const KAttrCN = "device.zpr.adapter.cn"

var zeroAddr = netip.Addr{}

// ConnectRec is collection of useful bits of data from
// policy "Connect" and "Proc" structs.
type ConnectRec struct {
	Flags    map[polio.FlagT]bool
	Attrs    map[string]*AExp
	Proc     *polio.Proc      // possibly nil
	Addr     netip.Addr       // parsed from Attrs
	CN       string           // parsed from Attrs
	Provides map[string]*SRec // from proc
}

// AExp is an attribute expression like the ones stored in a policy
// AddrOpT struct.
type AExp struct {
	Key   string
	Op    string // "EQ", "NE", "HAS", "EXCLUDES"
	Value string
}

// SRec is a "service record".  Holds info about a service registration.
type SRec struct {
	ServiceType string // eg "SVCT_DEF"
	Endpoints   []string
}

func NewConnectRec(attrs map[string]*AExp) *ConnectRec {
	rec := &ConnectRec{
		Flags:    make(map[polio.FlagT]bool),
		Attrs:    attrs,
		Provides: make(map[string]*SRec),
	}
	for k, kexp := range attrs {
		if k == "zpr.addr" && kexp.Op == "EQ" {
			rec.Addr = netip.MustParseAddr(kexp.Value)
		}
		if k == KAttrCN && kexp.Op == "EQ" {
			rec.CN = kexp.Value
		}
	}
	return rec
}

func NewConnectRecWithProc(attrs map[string]*AExp, proc *polio.Proc) *ConnectRec {
	rec := NewConnectRec(attrs)

	// If there are any service registrations, extrat them.
	for _, ins := range proc.Proc {
		if ins.Opcode == polio.OpCodeT_OP_Register {
			// The arguments are:
			//    0: (string) service name
			//    1: (service_type) service type enum
			//    2: (string) endpoints (comma separated list)
			args := ins.GetArgs()
			rec.Provides[args[0].GetStrval()] = &SRec{
				ServiceType: args[1].GetSvcval().String(),
				Endpoints:   strings.Split(args[2].GetStrval(), ","),
			}
		}
	}

	rec.Proc = proc
	return rec
}

func (rec *ConnectRec) SetFlag(flag polio.FlagT) {
	rec.Flags[flag] = true
}

func (rec *ConnectRec) IsNode() bool {
	return rec.Flags[polio.FlagT_F_NODE]
}

func (rec *ConnectRec) IsVisaService() bool {
	return rec.Flags[polio.FlagT_F_VISASERVICE]
}

func (rec *ConnectRec) IsVisaServiceDock() bool {
	return rec.Flags[polio.FlagT_F_VS_DOCK]
}

func (rec *ConnectRec) HasAddr() bool {
	return rec.Addr != zeroAddr && rec.Addr.IsValid()
}

// A node service registration uses the name "/zpr/<node-name>".
// This returns the node-name bit.
func (rec *ConnectRec) GetNodeName() string {
	for sname := range rec.Provides {
		if strings.HasPrefix(sname, "/zpr/") {
			bits := strings.Split(sname, "/")
			return bits[len(bits)-1]
		}
	}
	return ""
}

// Parse the policy attribute expression structure and rework into a map based one.
func attrExprToMap(attrExprs []*polio.AttrExpr, policy *polio.Policy) map[string]*AExp {
	attrs := make(map[string]*AExp)
	for _, expr := range attrExprs {
		key := policy.AttrKeyIndex[expr.Key]
		attrs[key] = &AExp{
			Key:   key,
			Op:    expr.Op.String(),
			Value: policy.AttrValIndex[expr.Val],
		}
	}
	return attrs
}

// Retruns true if the connect record has an attribute set using EQUALS with the given key.
func ConnectRecHasSetAttr(rec *ConnectRec, attrKey string) bool {
	if exp, ok := rec.Attrs[attrKey]; ok {
		return exp.Op == "EQ"
	}
	return false
}

// Find the connect record corresponding to the node.
func GetNodeConnect(policy *polio.Policy) *ConnectRec {
	// The node has a procedure that sets the F_NODE flag.
	connects := policy.GetConnects()
	if connects == nil {
		return nil
	}
	procs := policy.GetProcs()
	for _, cnct := range connects {
		if int(cnct.Proc) > len(procs) {
			continue
		}
		proc := procs[cnct.Proc]
		for _, ins := range proc.Proc {
			if ins.Opcode == polio.OpCodeT_OP_SetFlag && argsContains(ins.Args, polio.FlagT_F_NODE) {
				// Found the node.
				attrs := attrExprToMap(cnct.AttrExprs, policy)
				cr := NewConnectRecWithProc(attrs, proc)
				cr.SetFlag(polio.FlagT_F_NODE)
				return cr
			}
		}
	}
	return nil
}

// Lightly parse the policy Connect records and return.
func GetConnects(policy *polio.Policy) []*ConnectRec {
	var results []*ConnectRec
	connects := policy.GetConnects()
	if connects == nil {
		return nil
	}
	procs := policy.GetProcs()
	for _, cnct := range connects {
		attrs := attrExprToMap(cnct.AttrExprs, policy)
		if int(cnct.Proc) > len(procs) {
			// no proc.
			results = append(results, NewConnectRec(attrs))
		} else {
			proc := procs[cnct.Proc]
			cr := NewConnectRecWithProc(attrs, proc)
			for _, ins := range proc.Proc {
				for _, flag := range flags(ins.Args) {
					cr.SetFlag(flag)
				}
			}
			results = append(results, cr)
		}
	}
	return results
}

// Extract the the communication policies for the given service from the policy.
func GetCommPoliciesForService(policy *polio.Policy, service string) []*polio.CPolicy {
	var pols []*polio.CPolicy
	for _, cp := range policy.Policies {
		if cp.ServiceId == service {
			pols = append(pols, cp)
		}
	}
	return pols
}

// Generate a single endpoint of given protocol that is not in the provided scope.
func GenEndpointNotInScope(protocol uint32, scopes []*polio.Scope) *polio.Scope {
	existing := FilterScopeForProtocol(protocol, scopes)
	if existing == nil {
		return ScopeForProtocolPort(protocol, 1234)
	}
	// Else we need to pick a port not already allowed.
	candidatePort := uint32(packets.RandPort())
	inScope := make(map[uint16]bool)
	for _, scope := range existing {
		switch pa := scope.Protarg.(type) {
		case *polio.Scope_Pspec:
			for _, ps := range pa.Pspec.Spec {
				switch parg := ps.Parg.(type) {
				case *polio.PortSpec_Port:
					inScope[uint16(parg.Port)] = true
				case *polio.PortSpec_Pr:
					for p := parg.Pr.Low; p <= parg.Pr.High; p++ {
						inScope[uint16(p)] = true
					}
					if candidatePort >= parg.Pr.Low && candidatePort <= parg.Pr.High {
						// candidate port is in the range of an existing scope.
						candidatePort = parg.Pr.High + 1
						if candidatePort >= packets.MaxPort {
							candidatePort = packets.MinSrcPort
						}
					}
				}
			}
		}
	}
	if inScope[uint16(candidatePort)] {
		attempts := 0
		for inScope[uint16(candidatePort)] && attempts < packets.MaxPort {
			candidatePort++
			if candidatePort >= packets.MaxPort {
				candidatePort = packets.MinSrcPort
			}
			attempts++
		}
	}
	if inScope[uint16(candidatePort)] {
		panic("all endpoints in use")
	}
	return ScopeForProtocolPort(protocol, uint16(candidatePort))
}

// Create a new scope data structure that specifies the given protocol and port.
func ScopeForProtocolPort(protocol uint32, port uint16) *polio.Scope {
	return &polio.Scope{
		Protocol: protocol,
		Protarg: &polio.Scope_Pspec{
			Pspec: &polio.PortSpecList{
				Spec: []*polio.PortSpec{
					{
						Parg: &polio.PortSpec_Port{Port: uint32(port)},
					},
				},
			},
		},
	}
}

// Return scopes in the list that use the TCP protocol.
func FilterTCPScope(scopes []*polio.Scope) []*polio.Scope {
	return FilterScopeForProtocol(packets.ProtocolTCP, scopes)
}

// Return scopes in the list that use the given protocol.
func FilterScopeForProtocol(protocol uint32, scopes []*polio.Scope) []*polio.Scope {
	var results []*polio.Scope
	for _, scope := range scopes {
		if scope.Protocol == protocol {
			results = append(results, scope)
		}
	}
	return results
}

// Create a node actor data structure based on info in the policy.
func CreateNodeActor(pol *polio.Policy, expires time.Duration) (*vsapi.Actor, error) {
	nodeCR := GetNodeConnect(pol)
	if nodeCR == nil {
		return nil, fmt.Errorf("cannot createa node actor: no node connect information found in policy")
	}

	claims := make(map[string]string)
	if nodeCR.CN != "" {
		claims[KAttrCN] = nodeCR.CN
	}

	var provides []string
	for sname := range nodeCR.Provides {
		provides = append(provides, sname)
	}

	nodeAddr := nodeCR.Addr
	tetherAddr := nodeAddr

	nodeActor := vsapi.Actor{
		ActorType:   vsapi.ActorType_NODE,
		Attrs:       claims,
		AuthExpires: time.Now().Unix() + int64(expires.Seconds()),
		ZprAddr:     nodeAddr.AsSlice(),    // zpr address
		TetherAddr:  tetherAddr.AsSlice(),  // tether address
		Ident:       "ident-not-generated", // identity
		Provides:    provides,              // []string
	}
	return &nodeActor, nil
}

// Return TRUE if args contains the given flag.
func argsContains(args []*polio.Argument, arg polio.FlagT) bool {
	for _, a := range args {
		switch av := a.Arg.(type) {
		case *polio.Argument_Flagval:
			if av.Flagval == arg {
				return true
			}
		}
	}
	return false
}

// get all the flags in args list
func flags(args []*polio.Argument) []polio.FlagT {
	var fls []polio.FlagT
	for _, a := range args {
		switch av := a.Arg.(type) {
		case *polio.Argument_Flagval:
			fls = append(fls, av.Flagval)
		}
	}
	return fls
}

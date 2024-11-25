package conform

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"zpr.org/vst/pkg/vsapi"
	"zpr.org/vsx/polio"
)

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
		if k == "zpr.adapter.cn" && kexp.Op == "EQ" {
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

// The node has a procedure that sets the F_NODE flag.
func GetNodeConnect(policy *polio.Policy) *ConnectRec {
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

func CreateNodeAgent(pol *polio.Policy, expires time.Duration) (*vsapi.Agent, error) {
	nodeCR := GetNodeConnect(pol)
	if nodeCR == nil {
		return nil, fmt.Errorf("cannot createa node agent: no node connect information found in policy")
	}

	claims := make(map[string]string)
	if nodeCR.CN != "" {
		claims["zpr.adapter.cn"] = nodeCR.CN
	}

	var provides []string
	for sname := range nodeCR.Provides {
		provides = append(provides, sname)
	}

	nodeAddr := nodeCR.Addr
	tetherAddr := nodeAddr

	nodeAgent := vsapi.Agent{
		AgentType:   vsapi.AgentType_NODE,
		Attrs:       claims,
		AuthExpires: time.Now().Unix() + int64(expires.Seconds()),
		ZprAddr:     nodeAddr.AsSlice(),    // zpr address
		TetherAddr:  tetherAddr.AsSlice(),  // tether address
		Ident:       "ident-not-generated", // identity
		Provides:    provides,              // []string
	}
	return &nodeAgent, nil
}

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

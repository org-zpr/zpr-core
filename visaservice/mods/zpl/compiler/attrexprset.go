package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"zpr.org/vsx/zpl/doc"
)

// PSvcT is the PSvc type value
type PSvcT int

const (
	PSvcTDef       PSvcT = iota + 1 // default (regular service)
	PSvcTNode                       // Node
	PSvcTAuth                       // Auth
	PSvcTDecorator                  // Decorator
)

type AttrExprSet struct {
	ID        string          // Uniquely identify this entire struct
	AttrExprs []*doc.AttrExpr // KEY,OP,VAL ; all must be met
	Hash      string          // Shorthand, uniquely identifies the attribute expr set (plus connect_via)
	Provider  bool            // TRUE if this is a provider
	Node      bool            // TRUE if this identifies a node
	VSDock    bool            // TRUE if this (node) is a dock for a visa service adapter
	VSInst    bool            // TRUE if this (adapter) is running visa service
	Provides  []*PSvc         // what is provided - set of service "paths"
}

func (as *AttrExprSet) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("AttrExprSet{%v ", as.ID))
	if as.Node {
		sb.WriteString("*NODE* ")
	}
	if as.VSDock {
		sb.WriteString("*VS_DOCK* ")
	}
	if as.Provider {
		sb.WriteString(" PROVIDER [")
		for i, pp := range as.Provides {
			sb.WriteString(fmt.Sprintf("'%v'", pp.Path))
			if i > 0 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("] ")
	}
	sb.WriteString("hash=")
	sb.WriteString(as.Hash)
	sb.WriteString("}")
	return sb.String()
}

type SysPath struct {
	sys  *doc.System
	path string
}

type PSvc struct {
	Path      string // form is "/system_id/system_id/.../<service.Provides()>
	ServiceID string // service.provides()
	Type      PSvcT
	Endpoints []string // eg, 'tcp/80'
}

func (p *PSvc) String() string {
	return fmt.Sprintf("PSvc{'%v' (svcID=%v) T=%v endpoints=[%v]}", p.Path, p.ServiceID, p.Type, strings.Join(p.Endpoints, ", "))
}

func (t PSvcT) String() string {
	switch t {
	case PSvcTDef:
		return "PSDefault"
	case PSvcTNode:
		return "PSNode"
	case PSvcTAuth:
		return "PSAuth"
	default:
		return fmt.Sprintf("PSvcT<%d>", int(t))
	}
}

// GetProvides returns all the provides pathnames in the set.
func (as *AttrExprSet) GetProvides() string {
	var pnames []string
	for _, ps := range as.Provides {
		pnames = append(pnames, ps.Path)
	}
	return strings.Join(pnames, ", ")
}

// GenerateID compute the attribute hashes and IDs for the entire set. Updates `as`.
func (as *AttrExprSet) GenerateID() {
	// TODO:
	//   generate ID = HASH(Hash + Provides + Node)
	//
	sort.Slice(as.AttrExprs, func(i, j int) bool {
		if diff := strings.Compare(as.AttrExprs[i].Key.String(), as.AttrExprs[j].Key.String()); diff != 0 {
			return diff < 0
		}
		if diff := strings.Compare(as.AttrExprs[i].Op.String(), as.AttrExprs[j].Op.String()); diff != 0 {
			return diff < 0
		}
		return strings.Compare(as.AttrExprs[i].Value.String(), as.AttrExprs[j].Value.String()) < 0
	})
	as.Hash = func() string {
		h := sha256.New()
		for _, a := range as.AttrExprs {
			h.Write([]byte(a.Key.String()))
			h.Write([]byte(a.Op.String()))
			h.Write([]byte(a.Value.String()))
		}
		return hex.EncodeToString(h.Sum(nil))
	}()
	sort.Slice(as.Provides, func(i, j int) bool {
		return strings.Compare(as.Provides[i].Path, as.Provides[j].Path) < 0
	})
	as.ID = func() string {
		h := sha256.New()
		h.Write([]byte(as.Hash))
		for _, ps := range as.Provides {
			h.Write([]byte(ps.Path))
			h.Write([]byte{byte(ps.Type)})
			sort.Slice(ps.Endpoints, func(i, j int) bool {
				return strings.Compare(ps.Endpoints[i], ps.Endpoints[j]) < 0
			})
			h.Write([]byte(strings.Join(ps.Endpoints, ",")))
		}
		if as.Node {
			h.Write([]byte{0x1})
		} else {
			h.Write([]byte{0x0})
		}
		return hex.EncodeToString(h.Sum(nil))
	}()
}

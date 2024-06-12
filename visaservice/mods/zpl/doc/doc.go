package doc

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	ZPLFormat                     = 2       // expected ZPL format in a ZPL yaml file
	AuthAPIVersion                = "1.0.0" // Only supported auth API version
	DefaultMaxConnections         = 100
	DefaultMaxConnectionsPerDock  = 100
	DefaultNodeDockFlag           = true
	DefaultMaxConnectionsPerAgent = 1
	DefaultBridgeCost             = 1
	ICMPReqRep                    = "request-response" // ICMP type
	ICMPOnce                      = "oneshot"          // ICMP type
)

var (
	LegalProvidesCharsRE = regexp.MustCompile(`[^A-Za-z0-9\.\-]`)
)

// The structs defined below are typically populated with data from various
// "blocks" in a ZPL source. Many fields are of ZplScalar types (ZplString,
// etc.), each of which typically represents a scalar value from within such
// a block and also carries type information as well as a record of the location
// of the scalar within the ZPl source. The ZplRef fields that occur in these
// structs do not represent actual ZPL scalars (their Value methods return nil),
// but they carry type information about the locations of the corresponding
// blocks in the ZPL source. Location information allows the generation of
// informative error messages, e.g., with ZplScalarErrorf.

// Doc is the ZPL policy document in clean YAML (post pre-processing)
type Doc struct {
	ZplRef         ZplScalar
	ZPLFormat      ZplInteger
	Main           *Main
	Zpr            *ZPR
	Services       map[string]*Scoping
	Communications *Communications
}

type Main struct {
	ZplRef        ZplScalar
	PolicyVersion ZplUnsigned
	PolicyDate    ZplString // RFC3339
	PolicyDateUtc string    // RFC3339, UTC
}

type ZPR struct {
	ZplRef      ZplScalar
	Nodes       map[string]*Component // node_id -> node service description
	Topology    *Topology
	Visaservice *Visaservice
	Globals     *NetGlobs
	Datasources map[string]*Datasource // prefix -> datasource definition
}

type Visaservice struct {
	ZplRef   ZplScalar
	Dock     ZplString   // references a node ID
	Provider []*AttrExpr // To identify adapter hosting visa service
	Attrs    []*AttrExpr // PMCTL admin attributes
}

type NetGlobs struct {
	ZplRef                 ZplScalar
	MaxConnections         ZplUnsigned
	MaxConnectionsPerDock  ZplUnsigned
	MaxConnectionsPerAgent ZplUnsigned
}

type NetAddresses struct {
	ZplRef    ZplScalar
	TetherNet ZplString
	ZPRNet    ZplString
}

type Datasource struct {
	ZplRef    ZplScalar
	Api       ZplString
	Authority *Certificate
	Endpoint  *Endpoint
	Config    map[string]string
}

type Endpoint struct {
	ZplRef    ZplScalar
	Address   ZplString
	Provider  []*AttrExpr
	Services  []string // First one in list is the "auth" service to use
	TlsDomain ZplString
	TlsCert   *Certificate
	Policies  []*Policy // Optional
}

type Topology struct {
	ZplRef  ZplScalar
	LANs    map[string]*LANDesc // lan-name -> description
	Bridges []*Bridge
}

type LANDesc struct {
	ZplRef ZplScalar
	Nodes  []ZplString
}

type Bridge struct {
	ZplRef ZplScalar
	Nodes  []ZplString // pair of nodes
	Cost   ZplUnsigned
}

type Certificate struct {
	ZplRef   ZplScalar
	Encoding ZplString
	CertData ZplString
}

// Host is not currently used by ZPL parsing but is used elsewhere in the compiler.
type Host struct {
	Address  string // An IPv6 address or a hostname (may also be used in an "address" values below)
	addrIP   net.IP // filled in by by parser
	addrName string // filled in by parser
}

type Communications struct {
	ZplRef            ZplScalar
	Hierarchy         []ZplString
	Systems           map[string]*System     // System.ID -> System
	NestedDatasources map[string]*Datasource // we copy up the nested datasources here in the preprocessor
}

type System struct {
	ZplRef     ZplScalar
	ID         ZplString
	Desc       ZplString
	Hierarchy  ZplString             // corresponding element of Communications.Hierarchy
	Components map[string]*Component // Service.ID -> Service
	Systems    map[string]*System    // System.ID -> System (for subsystems)
}

// TODO won't need this any more
type Default struct {
	Desc  string
	Value interface{}
}

type Component struct {
	ZplRef       ZplScalar
	ID           ZplString
	Desc         ZplString
	Services     []string // Names reference into the global Services list.
	Provider     []*AttrExpr
	Auth         ZplString // reference a datasource prefix (inserted by compiler)
	Address      ZplString
	AddressSet   []ZplString
	SingleTenant ZplBoolean
	Decorator    ZplBoolean
	Policies     []*Policy
	Interfaces   map[string]*Interface // only for nodes
	Key          ZplString             // required for nodes
}

type Interface struct {
	ZplRef         ZplScalar
	Netaddr        ZplString   // HOST:PORT
	Dock           ZplBoolean  // Docking allowed? default true
	MaxConnections ZplUnsigned // Max dock connections
}

// TODO For now we're only using "eq" operators. If we decide to make that
// permanent, we should just drop Op from the AttrExpr struct and get rid
// of all the AttrExprOp*.
type AttrExpr struct {
	ZplRef ZplScalar
	Key    ZplString
	Op     ZplString
	Value  ZplScalar
}

const (
	AttrExprOpEq       = "eq"
	AttrExprOpNe       = "ne"
	AttrExprOpHas      = "has"
	AttrExprOpExcludes = "excludes"
)

func AllAttrExprOps() []string {
	return []string{AttrExprOpEq, AttrExprOpNe, AttrExprOpHas, AttrExprOpExcludes}
}

type Policy struct {
	ZplRef      ZplScalar
	Desc        ZplString
	ID          ZplString
	Services    []string // optional, and can only reference services defined in parent component
	Conditions  []*Condition
	Constraints *Constraint
}

type Scoping struct {
	ZplRef ZplScalar
	TCP    ZplString
	UDP    ZplString
	ICMP   *ScopeICMP
}

type ScopeICMP struct {
	ZplRef    ZplScalar
	Type      ZplString
	TypeCodes ZplString
}

type Condition struct {
	ZplRef    ZplScalar
	Desc      ZplString
	ID        ZplString
	AttrExprs []*AttrExpr
}

type Constraint struct {
	ZplRef     ZplScalar
	Bandwidth  ZplString
	Duration   ZplString
	AgentLimit ZplString
}

// IP returns the IP address if an IP address was specified in the host entry, or
// if resolution has already happened.  If host is just a name, then use h.Address
func (h *Host) IP() net.IP {
	return h.addrIP
}

func (h *Host) SetAddrIP(ip net.IP) {
	h.addrIP = ip
}
func (h *Host) SetAddrName(name string) {
	h.addrName = name
}

func (m *Main) SetDate(t time.Time) {
	m.PolicyDateUtc = t.UTC().Format(time.RFC3339)
	m.PolicyDate, _ = NewZplString(m.PolicyDateUtc)
}

// GetProvides returns the provides string for the service. This is the service name
// that will be used in ZPR.  This is the service ID.
func (s *Component) GetProvides() string {
	if s.ID.Value() == nil {
		panic("service without ID")
	}
	return s.ID.String()
}

func (s *Component) GetID() string {
	return s.GetProvides()
}

// GetID returns system ID if defined, else and ID based on system desc. Note that an ID is REQUIRED for a
// system block. This was not always the case and is why this is here.  Now this is being used as a
// sanity check to ensure and ID is there -- this will PANIC if the ID is not set.
func (sy *System) GetID() string {
	if sy.ID.Value() == nil {
		panic("system without an ID set")
	}
	return sy.ID.String()
}

func (e *AttrExpr) String() string {
	return fmt.Sprintf("( %v, %v, %v )", e.Key.String(), e.Op.String(), e.Value.String())
}

func (e *AttrExpr) Equal(other *AttrExpr) bool {
	if e == nil && other == nil {
		return true
	}
	if e == nil || other == nil {
		return false
	}
	return e.String() == other.String()
}

func (p *Policy) GetID() string {
	if p.ID.Value() == nil {
		return strings.Trim(LegalProvidesCharsRE.ReplaceAllString(p.Desc.String(), "-"), "-")
	}
	return p.ID.String()
}

func (c *Condition) GetID() string {
	if c.ID.Value() == nil {
		if c.Desc.Value() == nil {
			return ""
		} else {
			return strings.Trim(LegalProvidesCharsRE.ReplaceAllString(c.Desc.String(), "-"), "-")
		}
	}
	return c.ID.String()
}

func (sc *Scoping) String() string {
	if sc == nil {
		return ""
	}
	var sb strings.Builder
	if sc.ICMP != nil {
		sb.WriteString(fmt.Sprintf("ICMP/%v", sc.ICMP.TypeCodes.String()))
	}
	if sc.UDP.Value() != nil {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("UDP/%v", sc.UDP.String()))
	}
	if sc.TCP.Value() != nil {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("TCP/%v", sc.TCP.String()))
	}
	return sb.String()
}

package vservice

import (
	"net/netip"

	"zpr.org/vsx/snio/vsio"
)

// DirectoryService provides visa service with information about what's docked where.
// Part of the visa service support service on the node.
type DirectoryService interface {
	// AgentAtContactAddr returns the agent at the given contact address. Note that the existence of a
	// record here implies there is a route.
	// Must return an agent pointer or an error.
	AgentAtContactAddr(netip.Addr) (*vsio.Agent, error)

	// ZPRAddrForService should return all the ZPR contact addresses for the named service or nil if not found.
	//
	// Commented out since not needed in visa service (yet?).
	// ZPRAddrForService(string) []netip.Addr
}

// AgentRecord has all the fascinating details visa service needs when it is seeking info about agents.
//
// Visa service needs this information for all agents on the ZPRnet.
// The attributes are used when attempting to match an agent to a policy condition.
//
// TODO: why not use agent.Agent or vsio.Agent ?
/*
type AgentRecord struct {
	Attrs       map[string]*agent.ClaimV // These are the attributes that matched on connect.
	ConnectsVia netip.Addr               // Dock (must be a contact address)
	AuthExpire  time.Time
	Tether      netip.Addr // Agent tether address (IPv6)
	Provides    []string
	Ident       string // Agent ident not tied to any address
}
*/

type RConstraint struct {
	Origin        []byte
	Key           string
	CapBytes      uint64
	PeriodSeconds uint64
	PeriodStarts  uint64
	Consumed      uint64
}

// In the prototype we used RAFT on the nodes to keep track of the constraints.
//
// TODO: This needs to move to visa service.
type ConstraintService interface {
	ProposeConstraint(*RConstraint)
	ConstraintByKey(string) *RConstraint
}

func (c *RConstraint) GetCapBytes() uint64 {
	return c.CapBytes
}

func (c *RConstraint) GetPeriodStarts() uint64 {
	return c.PeriodStarts
}

// The visa service support interface will eventually also have functions to work with the
// constraint database.  For now this is just a dummy version.

type DummyConstraintService struct {
	db map[string]*RConstraint
}

func NewDummyConstraintService() *DummyConstraintService {
	return &DummyConstraintService{
		db: make(map[string]*RConstraint),
	}
}

func (dcs *DummyConstraintService) ProposeConstraint(c *RConstraint) {
	dcs.db[c.Key] = c
}

func (dcs *DummyConstraintService) ConstraintByKey(key string) *RConstraint {
	return dcs.db[key]
}

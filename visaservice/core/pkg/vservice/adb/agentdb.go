package adb

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vs/pkg/logr"
)

var (
	ErrorAgentExists = errors.New("agent already exists at address")
)

type Watcher interface {
	HandleDBAgentAdded(*agent.Agent)   // VSInst.AgentAdded
	HandleDBAgentRemoved(*agent.Agent) // VSInst.agentRemoved
}

// All agents in the system have a HostRecord.
// Nodes will have the Peer struct set.
type HostRecord struct {
	CTime        time.Time // connect/create time
	LastAuthTime time.Time
	Agent        *agent.Agent
	ZPRAddr      netip.Addr
	TetherAddr   netip.Addr
	Peer         *PeerRecord
	node         bool
}

// The visa-service "peers" are always nodes.
type PeerRecord struct {
	APIKey               string
	RegistrationTime     time.Time
	LastContactTime      time.Time
	VisaRequestsCount    uint64
	ConnectRequestsCount uint64
	VSSAddr              string
	pending              *PushBuffer
	State                struct {
		Updating          bool
		WantPolicyVer     uint64
		WantConfigID      uint64
		LastPushConfigID  uint64
		LastPushPolicyVer uint64
	}
}

type Ipv6Addr [16]byte

type AgentDB struct {
	sync.RWMutex
	agentsV6toHr map[Ipv6Addr]*HostRecord // Note we keep address in IPv6 format.
	watcher      Watcher
}

func (db *AgentDB) Dump(out logr.Logger) {
	db.RLock()
	defer db.RUnlock()

	out.Infof("===== dumping of agent database of size %d =====", len(db.agentsV6toHr))
	for addr, rec := range db.agentsV6toHr {
		atype := "adapter"
		if rec.node {
			atype = "node"
		}
		out.Infof("  [ %s ]  =>  (%v)  agent: %v; provides: %#v", addr, atype, rec.Agent.String(), rec.Agent.GetProvides())
	}
	out.Infof("===== dumping of agent database complete =====")
}

func NewAgentDB(watcher Watcher) *AgentDB {
	return &AgentDB{
		agentsV6toHr: make(map[Ipv6Addr]*HostRecord),
		watcher:      watcher,
	}
}

func NewPeerRecord() *PeerRecord {
	return &PeerRecord{
		pending: NewPushBuffer(),
	}
}

func (pr *PeerRecord) IsInSync() bool {
	return (pr.State.WantPolicyVer > 0 || pr.State.WantConfigID > 0) &&
		pr.State.WantPolicyVer == pr.State.LastPushPolicyVer &&
		pr.State.WantConfigID == pr.State.LastPushConfigID
}

func (db *AgentDB) Contains(addr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	_, found := db.agentsV6toHr[addr.As16()]
	return found
}

func (db *AgentDB) AddNode(zprAddr, tetherAddr netip.Addr, agent *agent.Agent, apiKey, vssAddr string) error {
	if db.Contains(zprAddr) {
		return ErrorAgentExists
	}
	rec := HostRecord{
		CTime:      time.Now(),
		Agent:      agent,
		ZPRAddr:    zprAddr,
		TetherAddr: tetherAddr,
		Peer:       NewPeerRecord(),
		node:       true,
	}
	rec.Peer.APIKey = apiKey
	rec.Peer.VSSAddr = vssAddr

	db.Lock()
	db.agentsV6toHr[zprAddr.As16()] = &rec
	db.Unlock()
	db.watcher.HandleDBAgentAdded(agent)
	return nil
}

// TODO: can get tether addr from agent.
func (db *AgentDB) AddAdapter(zprAddr, tetherAddr netip.Addr, agent *agent.Agent) error {
	if db.Contains(zprAddr) {
		return ErrorAgentExists
	}
	rec := HostRecord{
		CTime:      time.Now(),
		Agent:      agent,
		ZPRAddr:    zprAddr,
		TetherAddr: tetherAddr,
	}

	db.Lock()
	db.agentsV6toHr[zprAddr.As16()] = &rec
	db.Unlock()

	db.watcher.HandleDBAgentAdded(agent)
	return nil
}

func (db *AgentDB) AddOrUpdateAdapter(addr, tetherAddr netip.Addr, agnt *agent.Agent) error {
	if !db.Contains(addr) {
		return db.AddAdapter(addr, tetherAddr, agnt)
	}
	db.Lock()
	if rec, found := db.agentsV6toHr[addr.As16()]; found {
		rec.Agent = agnt
		rec.TetherAddr = tetherAddr
	}
	db.Unlock()
	return nil
}

// return true if found and deleted
func (db *AgentDB) RemoveNode(addr netip.Addr) bool {
	db.Lock()
	ipKey := addr.As16()
	rec, ok := db.agentsV6toHr[ipKey]
	if !ok {
		db.Unlock()
		return false
	}
	if !rec.node {
		db.Unlock()
		return false
	}
	delete(db.agentsV6toHr, ipKey)
	db.Unlock()

	db.watcher.HandleDBAgentRemoved(rec.Agent)
	return true
}

// True if found and removed
func (db *AgentDB) RemoveAdapter(addr netip.Addr) bool {
	db.Lock()
	db.Unlock()

	ipKey := addr.As16()
	rec, ok := db.agentsV6toHr[ipKey]
	if !ok {
		db.Unlock()
		return false
	}
	if rec.node {
		db.Unlock()
		return false
	}

	delete(db.agentsV6toHr, ipKey)
	db.Unlock()

	db.watcher.HandleDBAgentRemoved(rec.Agent)
	return true
}

// Note that any nodes that registered with IPv4 address have address returned here as Ipv4-in-IPv6.
func (db *AgentDB) GetNodeList() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var list []netip.Addr
	for addr, rec := range db.agentsV6toHr {
		if rec.node {
			list = append(list, netip.AddrFrom16(addr))
		}
	}
	return list
}

func (db *AgentDB) AgentAtContactAddr(addr netip.Addr) (*agent.Agent, error) {
	db.RLock()
	defer db.RUnlock()

	// Upgrade all IPv4 addresses to IPv4-in-IPv6
	if addr.Is4() {
		addr = netip.AddrFrom16(addr.As16())
	}

	rec, ok := db.agentsV6toHr[addr.As16()]
	if !ok {
		return nil, fmt.Errorf("agent %s not found", addr)
	}
	return rec.Agent, nil
}

func (db *AgentDB) DisableAPIKey(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()

	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.Peer != nil {
			rec.Peer.APIKey = ""
		}
	}
}

func (db *AgentDB) GetPeerRecord(addr netip.Addr) *PeerRecord {
	db.RLock()
	defer db.RUnlock()

	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node {
			return rec.Peer
		}
	}
	return nil
}

func (db *AgentDB) SetNodeContactTime(addr netip.Addr, t time.Time) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.LastContactTime = t
		}
	}
}

func (db *AgentDB) GetNodeLastContact(addr netip.Addr) (time.Time, bool) {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.LastContactTime, true
		}
	}
	return time.Time{}, false
}

func (db *AgentDB) DrainPending(addr netip.Addr) []*PushItem {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.pending.Drain()
		}
	}
	return nil
}

// also updates last contact time
func (db *AgentDB) IncrNodeConnectReq(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.ConnectRequestsCount++
			rec.Peer.LastContactTime = time.Now()
		}
	}
}

// also updates last contact time
func (db *AgentDB) IncrNodeVisaReq(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.VisaRequestsCount++
			rec.Peer.LastContactTime = time.Now()
		}
	}
}

func (db *AgentDB) IsNode(addr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		return rec.node
	}
	return false
}

func (db *AgentDB) GetNodeVSSAddr(addr netip.Addr) string {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.VSSAddr
		}
	}
	return ""
}

func (db *AgentDB) BufferItemsForNode(addr netip.Addr, items []*PushItem) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			for _, item := range items {
				rec.Peer.pending.Push(item)
			}
		}
	}
}

// Check the peer update status and set it to the given new value only if it is in the expected state.
// Returns (old_value, is_node_found?)
func (db *AgentDB) TestAndSetUpdating(addr netip.Addr, expected, newValue bool) (bool, bool) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			if rec.Peer.State.Updating == expected {
				rec.Peer.State.Updating = newValue
				return expected, true
			} else {
				return rec.Peer.State.Updating, true // not expected value
			}
		}
	}
	return false, false // not node or not found
}

// Note that node returned addresses here will have all been converted to IPv6.
func (db *AgentDB) GetOutOfSyncNonUpdatingNodes() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var nodes []netip.Addr
	for addrv6, rec := range db.agentsV6toHr {
		if rec.node && rec.Peer != nil && !rec.Peer.State.Updating && !rec.Peer.IsInSync() {
			nodes = append(nodes, netip.AddrFrom16(addrv6))
		}
	}
	return nodes
}

// Note that node returned addresses here will have all been converted to IPv6.
func (db *AgentDB) GetNodesWithPending() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var nodes []netip.Addr
	for addrv6, rec := range db.agentsV6toHr {
		if rec.node && rec.Peer != nil && rec.Peer.pending.Size() > 0 {
			nodes = append(nodes, netip.AddrFrom16(addrv6))
		}
	}
	return nodes
}

func (db *AgentDB) IsNodeUpdating(naddr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.agentsV6toHr[naddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.State.Updating
		}
	}
	return false
}

func (db *AgentDB) IsNodeInSync(naddr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.agentsV6toHr[naddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.IsInSync()
		}
	}
	return false
}

func (db *AgentDB) SetPeerDesiredPolicyState(addr netip.Addr, policyVer, configID uint64) bool {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.State.WantConfigID = configID
			rec.Peer.State.WantPolicyVer = policyVer
			return true
		}
	}
	return false
}

func (db *AgentDB) SetPeerLastPolicyState(addr netip.Addr, policyVer, configID uint64) bool {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.agentsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.State.LastPushConfigID = configID
			rec.Peer.State.LastPushPolicyVer = policyVer
			return true
		}
	}
	return false
}

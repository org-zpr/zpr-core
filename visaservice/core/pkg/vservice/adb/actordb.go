package adb

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"
)

var (
	ErrorActorExists = errors.New("actor already exists at address")
)

type Watcher interface {
	HandleDBActorAdded(*actor.Actor)   // VSInst.ActorAdded
	HandleDBActorRemoved(*actor.Actor) // VSInst.actorRemoved
}

// All actors in the system have a HostRecord.
// Nodes will have the Peer struct set.
type HostRecord struct {
	CTime        time.Time // connect/create time
	LastAuthTime time.Time
	Actor        *actor.Actor
	ZPRAddr      netip.Addr
	TetherAddr   netip.Addr
	Peer         *PeerRecord
	node         bool
}

// This type also shared with the visa admin api.
type HostRecordBrief struct {
	CTime   int64      `json:"ctime"` // unix seconds
	Cn      string     `json:"cn"`
	ZPRAddr netip.Addr `json:"zpr_addr"`
	Ident   string     `json:"ident"`
	Node    bool       `json:"node"`
}

// This type also shared with the visa admin api.
type NodeRecordBrief struct {
	InSync          bool       `json:"in_sync"`
	Pending         uint32     `json:"pending"`
	CTime           int64      `json:"ctime"`        // unix seconds
	LastContact     int64      `json:"last_contact"` // unix seconds
	VisaRequests    uint64     `json:"visa_requests"`
	ConnectRequests uint64     `json:"connect_requests"`
	ZPRAddr         netip.Addr `json:"zpr_addr"`
	Cn              string     `json:"cn"`
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
		LastSyncConfigID  uint64 // used by the bring-node-into-policy-sync system
		LastSyncPolicyVer uint64
		LastSyncVisasExp  time.Time
	}
}

type PeerSyncDetails struct {
	ConfigID        uint64
	PolicyVersion   uint64
	VisasExpiration time.Time
}

type Ipv6Addr [16]byte

type ActorDB struct {
	sync.RWMutex
	actorsV6toHr map[Ipv6Addr]*HostRecord // Note we keep address in IPv6 format.
	watcher      Watcher
}

func (db *ActorDB) Dump(out logr.Logger) {
	db.RLock()
	defer db.RUnlock()

	out.Infof("===== dumping of actor database of size %d =====", len(db.actorsV6toHr))
	for addr, rec := range db.actorsV6toHr {
		atype := "adapter"
		if rec.node {
			atype = "node"
		}
		out.Infof("  [ %s ]  =>  (%v)  actor: %v; provides: %#v", addr, atype, rec.Actor.String(), rec.Actor.GetProvides())
	}
	out.Infof("===== dumping of actor database complete =====")
}

func NewActorDB(watcher Watcher) *ActorDB {
	return &ActorDB{
		actorsV6toHr: make(map[Ipv6Addr]*HostRecord),
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

func (db *ActorDB) Contains(addr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	_, found := db.actorsV6toHr[addr.As16()]
	return found
}

func (db *ActorDB) AddNode(zprAddr, tetherAddr netip.Addr, actor *actor.Actor, apiKey, vssAddr string) error {
	if db.Contains(zprAddr) {
		return ErrorActorExists
	}
	rec := HostRecord{
		CTime:      time.Now(),
		Actor:      actor,
		ZPRAddr:    zprAddr,
		TetherAddr: tetherAddr,
		Peer:       NewPeerRecord(),
		node:       true,
	}
	rec.Peer.APIKey = apiKey
	rec.Peer.VSSAddr = vssAddr

	db.Lock()
	db.actorsV6toHr[zprAddr.As16()] = &rec
	db.Unlock()
	db.watcher.HandleDBActorAdded(actor)
	return nil
}

// TODO: can get tether addr from actor.
func (db *ActorDB) AddAdapter(zprAddr, tetherAddr netip.Addr, actor *actor.Actor) error {
	if db.Contains(zprAddr) {
		return ErrorActorExists
	}
	rec := HostRecord{
		CTime:      time.Now(),
		Actor:      actor,
		ZPRAddr:    zprAddr,
		TetherAddr: tetherAddr,
	}

	db.Lock()
	db.actorsV6toHr[zprAddr.As16()] = &rec
	db.Unlock()

	db.watcher.HandleDBActorAdded(actor)
	return nil
}

func (db *ActorDB) AddOrUpdateAdapter(addr, tetherAddr netip.Addr, agnt *actor.Actor) error {
	if !db.Contains(addr) {
		return db.AddAdapter(addr, tetherAddr, agnt)
	}
	db.Lock()
	if rec, found := db.actorsV6toHr[addr.As16()]; found {
		rec.Actor = agnt
		rec.TetherAddr = tetherAddr
	}
	db.Unlock()
	return nil
}

// return true if found and deleted
func (db *ActorDB) RemoveNode(addr netip.Addr) bool {
	db.Lock()
	ipKey := addr.As16()
	rec, ok := db.actorsV6toHr[ipKey]
	if !ok {
		db.Unlock()
		return false
	}
	if !rec.node {
		db.Unlock()
		return false
	}
	delete(db.actorsV6toHr, ipKey)
	db.Unlock()

	db.watcher.HandleDBActorRemoved(rec.Actor)
	return true
}

// True if found and removed
func (db *ActorDB) RemoveAdapter(addr netip.Addr) bool {
	db.Lock()

	ipKey := addr.As16()
	rec, ok := db.actorsV6toHr[ipKey]
	if !ok {
		db.Unlock()
		return false
	}
	if rec.node {
		db.Unlock()
		return false
	}

	delete(db.actorsV6toHr, ipKey)
	db.Unlock()

	db.watcher.HandleDBActorRemoved(rec.Actor)
	return true
}

// Note that any nodes that registered with IPv4 address have address returned here as Ipv4-in-IPv6.
func (db *ActorDB) GetNodeList() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var list []netip.Addr
	for addr, rec := range db.actorsV6toHr {
		if rec.node {
			list = append(list, netip.AddrFrom16(addr))
		}
	}
	return list
}

// Copies all the actor records into "brief" format and returns them.
func (db *ActorDB) CloneToBrief() []*HostRecordBrief {
	db.RLock()
	defer db.RUnlock()
	var list []*HostRecordBrief
	for _, rec := range db.actorsV6toHr {
		var cn string
		if claim, ok := rec.Actor.GetAuthedClaims()[actor.KAttrCN]; ok {
			cn = claim.V
		} else {
			cn = ""
		}
		list = append(list, &HostRecordBrief{
			CTime:   rec.CTime.Unix(),
			Cn:      cn,
			ZPRAddr: rec.ZPRAddr,
			Ident:   rec.Actor.GetIdentity(),
			Node:    rec.node,
		})
	}
	return list
}

// Copies all the node records into "brief" format and returns them.
func (db *ActorDB) CloneNodesToBrief() []*NodeRecordBrief {
	db.RLock()
	defer db.RUnlock()
	var list []*NodeRecordBrief
	for _, rec := range db.actorsV6toHr {
		if rec.node {
			brief := &NodeRecordBrief{
				CTime:           rec.CTime.Unix(),
				Cn:              "",
				ZPRAddr:         rec.ZPRAddr,
				LastContact:     0,
				VisaRequests:    0,
				ConnectRequests: 0,
				InSync:          false,
			}
			if claim, ok := rec.Actor.GetAuthedClaims()[actor.KAttrCN]; ok {
				brief.Cn = claim.V
			}
			if rec.Peer != nil {
				if !rec.Peer.LastContactTime.IsZero() {
					brief.LastContact = rec.Peer.LastContactTime.Unix()
				}
				brief.InSync = rec.Peer.IsInSync()
				brief.Pending = uint32(rec.Peer.pending.Size())
				brief.VisaRequests = rec.Peer.VisaRequestsCount
				brief.ConnectRequests = rec.Peer.ConnectRequestsCount
			}
			list = append(list, brief)
		}
	}
	return list
}

// ActorAtContactAddr returns the actor record for the given address.
// The only error condifition is if the actor is not found.
func (db *ActorDB) ActorAtContactAddr(addr netip.Addr) (*actor.Actor, error) {
	db.RLock()
	defer db.RUnlock()

	// Upgrade all IPv4 addresses to IPv4-in-IPv6
	if addr.Is4() {
		addr = netip.AddrFrom16(addr.As16())
	}

	rec, ok := db.actorsV6toHr[addr.As16()]
	if !ok {
		return nil, fmt.Errorf("actor %s not found", addr)
	}
	return rec.Actor, nil
}

func (db *ActorDB) DisableAPIKey(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()

	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.Peer != nil {
			rec.Peer.APIKey = ""
		}
	}
}

func (db *ActorDB) GetPeerRecord(addr netip.Addr) *PeerRecord {
	db.RLock()
	defer db.RUnlock()

	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node {
			return rec.Peer
		}
	}
	return nil
}

func (db *ActorDB) SetNodeContactTime(addr netip.Addr, t time.Time) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.LastContactTime = t
		}
	}
}

func (db *ActorDB) GetNodeLastContact(addr netip.Addr) (time.Time, bool) {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.LastContactTime, true
		}
	}
	return time.Time{}, false
}

func (db *ActorDB) DrainPending(addr netip.Addr) []*PushItem {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.pending.Drain()
		}
	}
	return nil
}

// also updates last contact time
func (db *ActorDB) IncrNodeConnectReq(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.ConnectRequestsCount++
			rec.Peer.LastContactTime = time.Now()
		}
	}
}

// also updates last contact time
func (db *ActorDB) IncrNodeVisaReq(addr netip.Addr) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.VisaRequestsCount++
			rec.Peer.LastContactTime = time.Now()
		}
	}
}

func (db *ActorDB) IsNode(addr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		return rec.node
	}
	return false
}

func (db *ActorDB) GetNodeVSSAddr(addr netip.Addr) string {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.VSSAddr
		}
	}
	return ""
}

func (db *ActorDB) BufferItemsForNode(addr netip.Addr, items []*PushItem) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			for _, item := range items {
				rec.Peer.pending.Push(item)
			}
		}
	}
}

func (db *ActorDB) GetPeerSyncDetails(nodeAddr netip.Addr) *PeerSyncDetails {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[nodeAddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return &PeerSyncDetails{
				ConfigID:        rec.Peer.State.LastSyncConfigID,
				PolicyVersion:   rec.Peer.State.LastSyncPolicyVer,
				VisasExpiration: rec.Peer.State.LastSyncVisasExp,
			}
		}
	}
	return nil
}

func (db *ActorDB) SetPeerSyncDetails(nodeAddr netip.Addr, polVersion, configID uint64, visasExpiration time.Time) error {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[nodeAddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.State.LastSyncConfigID = configID
			rec.Peer.State.LastSyncPolicyVer = polVersion
			rec.Peer.State.LastSyncVisasExp = visasExpiration
			return nil
		}
	}
	return fmt.Errorf("node not found")
}

// Check the peer update status and set it to the given new value only if it is in the expected state.
// Returns (old_value, is_node_found?)
func (db *ActorDB) TestAndSetUpdating(addr netip.Addr, expected, newValue bool) (bool, bool) {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
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
func (db *ActorDB) GetOutOfSyncNonUpdatingNodes() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var nodes []netip.Addr
	for addrv6, rec := range db.actorsV6toHr {
		if rec.node && rec.Peer != nil && !rec.Peer.State.Updating && !rec.Peer.IsInSync() {
			nodes = append(nodes, netip.AddrFrom16(addrv6))
		}
	}
	return nodes
}

// Note that node returned addresses here will have all been converted to IPv6.
func (db *ActorDB) GetNodesWithPending() []netip.Addr {
	db.RLock()
	defer db.RUnlock()
	var nodes []netip.Addr
	for addrv6, rec := range db.actorsV6toHr {
		if rec.node && rec.Peer != nil && rec.Peer.pending.Size() > 0 {
			nodes = append(nodes, netip.AddrFrom16(addrv6))
		}
	}
	return nodes
}

func (db *ActorDB) IsNodeUpdating(naddr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[naddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.State.Updating
		}
	}
	return false
}

func (db *ActorDB) IsNodeInSync(naddr netip.Addr) bool {
	db.RLock()
	defer db.RUnlock()
	if rec, ok := db.actorsV6toHr[naddr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			return rec.Peer.IsInSync()
		}
	}
	return false
}

func (db *ActorDB) SetPeerDesiredPolicyState(addr netip.Addr, policyVer, configID uint64) bool {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.State.WantConfigID = configID
			rec.Peer.State.WantPolicyVer = policyVer
			return true
		}
	}
	return false
}

func (db *ActorDB) SetPeerLastPolicyState(addr netip.Addr, policyVer, configID uint64) bool {
	db.Lock()
	defer db.Unlock()
	if rec, ok := db.actorsV6toHr[addr.As16()]; ok {
		if rec.node && rec.Peer != nil {
			rec.Peer.State.LastPushConfigID = configID
			rec.Peer.State.LastPushPolicyVer = policyVer
			return true
		}
	}
	return false
}

// Does full search of database.
func (db *ActorDB) GetActorsWithClaim(key, val string) []*actor.Actor {
	db.RLock()
	defer db.RUnlock()
	var actors []*actor.Actor
	for _, rec := range db.actorsV6toHr {
		if rec.Actor.HasAuthedClaim(key, val) {
			actors = append(actors, rec.Actor)
		}
	}
	return actors
}

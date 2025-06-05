package vservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt" // not used for crypto
	"net/netip"
	"sync"
	"time"

	"github.com/apache/thrift/lib/go/thrift"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/adb"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"
)

var (
	ErrNoRouteToHost  = errors.New("no route to host")
	ErrDeniedByPolicy = errors.New("denied by policy")
	ErrVSMisconfigure = errors.New("visa service misconfigured")
	ErrAuthExpired    = errors.New("auth expired")
	ErrVisaNotFound   = errors.New("visa not found")
)

type HelloRecord struct {
	CTime  time.Time
	Chksum uint32
}

type VSMsgType int

const (
	MTNodeRegister VSMsgType = iota + 1
	MTApproveConnection
)

type VSMsg struct {
	MsgType        VSMsgType
	NodeAddr       netip.Addr
	ConnectRequest *vsapi.ConnectRequest // for MTApproveConnection
	ReplyC         chan *VSMsgDone
}

type VSMsgDone struct {
	MsgType VSMsgType
	Err     error
	Actor   *actor.Actor
}

// VSInst is an instance of distributed visa service
//
// This is a bit of a mess at the moment as we are in progress of porting this from
// old code in machine.go and network.go.
type VSInst struct {
	log                   logr.Logger
	vlog                  *Vlog
	hopCount              uint
	authr                 auth.AuthService
	attrProx              *AttrProxy
	visaPushC             chan *adb.PushItem // For pushing visas without needing a request
	nodeNumber            uint8
	nodeState             ConstraintService
	thriftServer          thrift.TServer
	vsMsgC                chan *VSMsg
	localAddr             netip.Addr
	thriftWg              sync.WaitGroup
	thriftCreds           *tls.Config
	exitC                 chan struct{}
	reauthBumpTime        time.Duration
	accessToken           []byte // Access token for special node operations
	allowInvalidPeerAddr  bool   // Set to TRUE for testing only.
	actorDB               *adb.ActorDB
	bootstrapAuthDuration time.Duration
	authorityCert         *x509.Certificate // for checking certififactes from nodes/adapters

	cfgRemoves struct {
		sync.Mutex
		removes []*configRemoval // ordered earliest to latest
	}

	plcy struct {
		sync.RWMutex
		p       *policy.Policy  // current policy
		cid     uint64          // current config ID
		matcher *policy.Matcher // extracted from current policy
	}

	vtable struct {
		mtx        sync.RWMutex
		nextVisaID uint32
		table      map[uint32]*vtableEnt // Visas created
	}

	sessions struct {
		sync.RWMutex
		hellos  map[int32]*HelloRecord
		apiKeys map[string]netip.Addr // ZPR Addr (can use to lookup in the actor DB)
	}
}

// configRemoval to track when a net-config is supplanted.
type configRemoval struct {
	config  uint64    // old net config ID
	removal time.Time // was supplanted at this time
}

// vtableEnt is an entry in our visa table (VSInst.vtable)
type vtableEnt struct {
	v         *vsapi.Visa
	isVSVisa  bool          // TRUE if this is a visa for visa service access
	pktData   *snip.Traffic // Packet descriptor used on visa request
	successor uint32        // 0 means no successor
}

// VSIConfig is the rather complex configuration bundle for the visa service.
type VSIConfig struct {
	Log                    logr.Logger   // General logging
	VSAddr                 netip.Addr    // Visa service ZPR public address
	HopCount               uint          // Is set on every visa we create
	CN                     string        // Visa service CN value used by the vs adapter
	Creds                  *tls.Config   // TLS for the thrift channel
	ReauthBumpTimeOverride time.Duration // For unit testing (see DefaultReauthBumpTime defined above)
	AccessToken            []byte        // Auth token for node to access special VS capabilities
	AllowInvalidPeerAddr   bool          // Set to TRUE for testing only.
	Constrainer            ConstraintService
	BootstrapAuthDuration  time.Duration
	AuthorityCert          *x509.Certificate // for checking certififactes from nodes/adapters
}

var EMPTY_ADDR = netip.Addr{}

// NewVSInst create a new visa service.
func NewVSInst(vcf *VSIConfig) (*VSInst, error) {
	if vcf.VSAddr == EMPTY_ADDR || vcf.VSAddr.IsUnspecified() {
		return nil, fmt.Errorf("visa service address 'VSAddr' must be set")
	}
	if vcf.CN == "" {
		return nil, fmt.Errorf("visa service CN must be set")
	}
	if vcf.AuthorityCert == nil {
		return nil, fmt.Errorf("authority certificate must be set")
	}

	vs := &VSInst{
		log:                   vcf.Log,
		localAddr:             vcf.VSAddr,
		hopCount:              vcf.HopCount,
		visaPushC:             make(chan *adb.PushItem, 128), // Must be large enough to handle a mass revocation event
		thriftCreds:           vcf.Creds,
		reauthBumpTime:        DefaultReauthBumpTime,
		exitC:                 make(chan struct{}),
		accessToken:           vcf.AccessToken,
		allowInvalidPeerAddr:  vcf.AllowInvalidPeerAddr,
		nodeState:             vcf.Constrainer,
		vsMsgC:                make(chan *VSMsg, 16),
		bootstrapAuthDuration: vcf.BootstrapAuthDuration,
		authorityCert:         vcf.AuthorityCert,
	}
	if vcf.ReauthBumpTimeOverride > 0 {
		vs.reauthBumpTime = vcf.ReauthBumpTimeOverride
	}
	vs.vtable.table = make(map[uint32]*vtableEnt)
	vs.vtable.nextVisaID = minVisaID
	vs.sessions.apiKeys = make(map[string]netip.Addr)
	vs.sessions.hellos = make(map[int32]*HelloRecord)
	vs.actorDB = adb.NewActorDB(vs)

	nopol := policy.NewEmptyPolicy()
	vs.plcy.p = nopol
	vs.plcy.cid = policy.InitialConfiguration
	if m, err := policy.NewMatcher(nopol.ExportBundle(), policy.InitialConfiguration, vcf.Log); err != nil {
		return nil, err
	} else {
		vs.plcy.matcher = m
	}

	// We need a visa service actor to exist.
	// TODO: These claims need to come from configuration. Note that the adapter holds the claims
	//       for the visa service actor.
	//
	// TODO: In prototype, the dock attached to the visa service adapter would evetually authenticate with the
	//       visa service after bootstrap.  We need to do something like that too.
	visaServiceActor := actor.NewActorFromUnsubstantiatedClaims(nil)
	{
		visaServiceActor.SetProvides([]string{
			policy.VisaServiceName,
			fmt.Sprintf("/zpr/%s", policy.VisaServiceName),
			fmt.Sprintf("/zpr/%s/admin", policy.VisaServiceName),
		})
		authedClaims := make(map[string]*actor.ClaimV)
		authedClaims[actor.KAttrVisaServiceAdapter] = &actor.ClaimV{
			V:   "true",
			Exp: time.Now().Add(vs.bootstrapAuthDuration),
		}
		authedClaims[actor.KAttrEPID] = &actor.ClaimV{
			V:   vcf.VSAddr.String(),
			Exp: time.Now().Add(vs.bootstrapAuthDuration),
		}
		authedClaims[actor.KAttrCN] = &actor.ClaimV{
			V:   vcf.CN,
			Exp: time.Now().Add(vs.bootstrapAuthDuration),
		}
		visaServiceActor.SetTetherAddr(vcf.VSAddr)
		visaServiceActor.SetAuthenticated(authedClaims, time.Now().Add(vs.bootstrapAuthDuration), nil, nil, 0)
	}

	if err := vs.actorDB.AddAdapter(vcf.VSAddr, visaServiceActor.GetTetherAddr(), visaServiceActor); err != nil {
		return nil, fmt.Errorf("failed to add visa service actor")
	}

	vs.log.Info("visa service instance configured", "reauthBumpTime", vs.reauthBumpTime.String())
	return vs, nil
}

func (vs *VSInst) SetAuthSvc(a auth.AuthService) {
	vs.authr = a
	vs.attrProx = NewAttrProxy(a)
}

// Start is blocking call to start the visa service THRIFT listener.
// Also sets this visa services local address.
func (vs *VSInst) Start(listenAddr netip.Addr, port uint16) error {

	vlog, err := NewVlogToFile("visa.log")
	if err != nil {
		return fmt.Errorf("failed to create visa log: %w", err)
	}
	vs.vlog = vlog
	defer vlog.Close()

	vs.thriftWg.Add(1)
	go func() {
		defer vs.thriftWg.Done()
		thrift.ServerStopTimeout = 5 * time.Second // TODO: Should come from config
		if err := vs.startThriftBlocking(listenAddr, port); err != nil {
			vs.log.WithError(err).Error("visa service start failed")
		}
	}()

	tkr := time.NewTicker(15 * time.Second)
	defer tkr.Stop()
VS_RUNLOOP:
	for {
		select {
		case m, ok := <-vs.vsMsgC:
			if ok {
				switch m.MsgType {
				case MTNodeRegister:
					vs.handleNodeRegister(m.NodeAddr)
				case MTApproveConnection:
					vs.handleApproveConnection(m.ConnectRequest, m.ReplyC)
				}
			}

		case now := <-tkr.C:
			vs.periodicHousekeeping(now)

		case req, ok := <-vs.visaPushC: // Drain this push channel
			if ok {
				vs.pushToNode(req)
			}

		case <-vs.exitC:
			break VS_RUNLOOP
		}
	}

	vs.log.Info("visa service runloop exiting")
	return nil
}

func (vs *VSInst) Stop() {
	vs.thriftServer.Stop()
	vs.thriftWg.Wait()
	close(vs.exitC) // stop runloop
}

// Implement policy.Configurator interface.
// TODO: Pretty sure this is irrelevant for the visa service.  Was (is?) used to alter some configuration values
// on a node.  For now logging when this is used to see if we need it.
func (vs *VSInst) SetConfig(key, value string) error {
	vs.log.Info("XXX ==configurator== SET_CONFIG (NOP!!) >>", "key", key, "value", value)
	return nil
}

// periodicHousekeeping is called from runloop (and so blocks runloop).
func (vs *VSInst) periodicHousekeeping(now time.Time) {
	vs.log.Debug("periodic housekeeping starts")
	vs.extendVisaServiceVisas()
	vs.removeExpiredVisas()
	vs.expireOldConfiguration()
	vs.checkNodesVSSState()
	vs.checkPushBuffers()
	vs.log.Debug("periodic housekeeping ends", "elapsed", time.Since(now).String())
}

// RunPeriodicHousekeepingNow is here for unit tests only. Do not call outside of unit tests.
func (vs *VSInst) RunPeriodicHousekeepingNow() {
	vs.periodicHousekeeping(time.Now())
}

// expireOldConfiguration expires the oldest configuration change which has exceeded
// the settling time. Should only be called from run loop.
func (vs *VSInst) expireOldConfiguration() {
	vs.cfgRemoves.Lock()
	defer vs.cfgRemoves.Unlock()
	if len(vs.cfgRemoves.removes) > 0 {
		if time.Since(vs.cfgRemoves.removes[0].removal) >= NetConfigSettleTime {
			vs.log.Info("expunging old configuration", "net_config", vs.cfgRemoves.removes[0].config)
			vs.expireAllVisas(vs.cfgRemoves.removes[0].config)
			var popped []*configRemoval
			for i, r := range vs.cfgRemoves.removes {
				if i == 0 {
					continue
				}
				popped = append(popped, r)
			}
			vs.cfgRemoves.removes = popped
		}
	}
}

// extendVisaServiceVisas runs through the visa table and looks for visa-service
// visas that are expiring "soon". If any are found they are re-uppped.
func (vs *VSInst) extendVisaServiceVisas() {
	// prevent visa updates while running:
	vs.plcy.RLock()
	defer vs.plcy.RUnlock()

	var expiringVisas []*vtableEnt

	// Run through table and grab any about-to-expire visa-service visas.
	vs.vtable.mtx.RLock()
	for _, ve := range vs.vtable.table {
		if ve.isVSVisa && (ve.successor == 0) {
			remain := time.Until(libvisa.VToTime(ve.v.GetExpires()))
			if remain < VSVisaRenewalTime {
				sourceAddr, _ := netip.AddrFromSlice(ve.v.Source)
				agnt, err := vs.actorDB.ActorAtContactAddr(sourceAddr) // for a node contact_addr is visa "tether" addr.
				if err != nil || agnt == nil {
					continue // actor is gone
				}
				expiringVisas = append(expiringVisas, ve)
			}
		}
	}
	vs.vtable.mtx.RUnlock()
	if sz := len(expiringVisas); sz > 0 {
		vs.log.Info("extending visa-service visas", "count", sz)
	}
	// Create a new visa with same parameters as original, and push to nodes.
	// We set a minimum expiration just in case visa expiration mechanism chooses one
	// that is within our VSVisaRenewalTime, which would cause an endless loop.
	vs.rerequestVisas(expiringVisas, (2 * VSVisaRenewalTime), true, vs.plcy.p.VersionNumber())
}

// rerequestVisas requests "successor" visas for the visas in the passed list.
func (vs *VSInst) rerequestVisas(xvisas []*vtableEnt, minDuration time.Duration, push bool, expectedPolicyID uint64) {
	for _, ve := range xvisas {
		sourceTetherAddr, _ := netip.AddrFromSlice(ve.v.Source)
		vs.log.Debug("invoking request-visa for re-request visa processing")
		resp, err := vs.doRequestVisa(context.Background(), sourceTetherAddr, ve.pktData, minDuration, expectedPolicyID)
		if err != nil {
			vs.log.WithError(err).Error("failed to re-request visa")
		} else {
			vs.vtable.mtx.Lock()
			if rec, ok := vs.vtable.table[uint32(ve.v.IssuerID)]; ok {
				rec.successor = uint32(resp.Visa.IssuerID)
			} else {
				vs.log.Error("failed to locate predecessor visa in table", "issuerID", ve.v.IssuerID)
			}
			// vs.dumpVisaTableHoldingLock("rerequest")
			vs.vtable.mtx.Unlock()
			if push {
				// TODO: To push the visa we need to know which nodes need this.
				//       I think we used to put this in the mailbox for all nodes,
				//       for now I am doing a search here to find the correct node(s)
				//       to push to.
				targetNodes := make(map[netip.Addr]bool)
				for _, addr := range [][]byte{ve.v.Source, ve.v.Dest, ve.v.SourceContact, ve.v.DestContact} {
					if a, ok := netip.AddrFromSlice(addr); ok {
						if vs.actorDB.IsNode(a) {
							targetNodes[a] = true
						}
					}
				}
				for a := range targetNodes {
					vs.EnqueuePushVisasToNode(a, []*vsapi.VisaHop{resp.Visa})
				}
			}
		}
	}
}

func (vs *VSInst) removeExpiredVisas() {
	vs.vtable.mtx.Lock()
	defer vs.vtable.mtx.Unlock()
	curTS := libvisa.VTimeNow()
	for vid, vv := range vs.vtable.table {
		if curTS > vv.v.GetExpires() {
			vs.log.Info("visa has expired", "visaID", vid)
			delete(vs.vtable.table, vid)
		}
	}
	// vs.dumpVisaTableHoldingLock("removeExpired")
}

// expireAllVisas is called when policy is updated.  Revokes and removes all visas under the
// given network configuration.
func (vs *VSInst) expireAllVisas(config uint64) {
	configI64 := int64(config)
	vs.vtable.mtx.Lock()
	defer vs.vtable.mtx.Unlock()
	count := 0
	var revokes []*vsapi.VisaRevocation
	for vID, ve := range vs.vtable.table {
		if ve.v.Configuration == configI64 {
			revokes = append(revokes, &vsapi.VisaRevocation{
				IssuerID:      int32(vID),
				Configuration: configI64,
			})
			delete(vs.vtable.table, vID)
			count++
		}
	}
	vs.log.Infof("%d visas revoked due to configuration change", count)
	push := adb.PushItem{
		Broadcast:   true,
		Revocations: revokes,
	}
	// We are often called from runloop so blocking here would be bad.
	select {
	case vs.visaPushC <- &push: // ok
	default:
		vs.log.Warn("push channel full, failed to issue revoke, continuing")
	}
}

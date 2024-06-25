package vservice

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/rand" // not used for crypto
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"zpr.org/vs/pkg/agent"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsx/snio/vsio"
	"zpr.org/vsx/snio/zds"
)

var (
	ErrNoRouteToHost  = errors.New("no route to host")
	ErrDeniedByPolicy = errors.New("denied by policy")
	ErrVSMisconfigure = errors.New("visa service misconfigured")
	ErrAuthExpired    = errors.New("auth expired")
)

// The visa-service "peers" are always nodes.
type PeerRecord struct {
	ZPRAddr              netip.Addr // can use to lookup in agentDB
	RegistrationTime     time.Time
	LastPollTime         time.Time
	VisaRequestsCount    uint64
	ConnectRequestsCount uint64
}

type HelloRecord struct {
	CTime  time.Time
	Chksum uint32
}

type HostRecord struct {
	CTime        time.Time // connect/create time
	LastAuthTime time.Time
	Agent        *agent.Agent
	ZPRAddr      netip.Addr
	TetherAddr   netip.Addr
	APIKey       string
}

// VSInst is an instance of distributed visa service
//
// This is a bit of a mess at the moment as we are in progress of porting this from
// old code in machine.go and network.go.
type VSInst struct {
	log                  logr.Logger
	vlog                 *Vlog
	hopCount             uint
	authr                auth.AuthService
	attrProx             *AttrProxy
	visaPushC            chan *vsapi.PollResponse // For pushing visas without needing a request
	nodeNumber           uint8
	nodeState            ConstraintService
	thriftServer         thrift.TServer
	localAddr            netip.Addr
	grpcWg               sync.WaitGroup
	grpcCreds            credentials.TransportCredentials
	exitC                chan struct{}
	mb                   *Mailbox
	reauthBumpTime       time.Duration
	accessToken          []byte // Access token for special node operations
	agentSigningKey      *rsa.PrivateKey
	allowInvalidPeerAddr bool // Set to TRUE for testing only.

	agentDB struct {
		sync.RWMutex
		agents map[netip.Addr]*HostRecord // ZPR_CONTACT_ADDR -> HostRecord
	}

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
		apiKeys map[string]*PeerRecord
	}
}

// configRemoval to track when a net-config is supplanted.
type configRemoval struct {
	config  uint64    // old net config ID
	removal time.Time // was supplanted at this time
}

// vtableEnt is an entry in our visa table (VSInst.vtable)
type vtableEnt struct {
	v         *vsio.Visa
	isVSVisa  bool          // TRUE if this is a visa for visa service access
	pktData   *snip.Traffic // Packet descriptor used on visa request
	successor uint32        // 0 means no successor
}

// VSIConfig is the rather complex configuration bundle for the visa service.
type VSIConfig struct {
	Log                    logr.Logger                      // General logging
	HopCount               uint                             // Is set on every visa we create
	Creds                  credentials.TransportCredentials // For server side TLS for the PMCTL and the Visa-Service channels
	ReauthBumpTimeOverride time.Duration                    // For unit testing (see DefaultReauthBumpTime defined above)
	AccessToken            []byte                           // Auth token for node to access special VS capabilities
	AgentSigningKey        *rsa.PrivateKey
	AllowInvalidPeerAddr   bool // Set to TRUE for testing only.
	Constrainer            ConstraintService
}

// NewVSInst create a new visa service.
func NewVSInst(vcf *VSIConfig) (*VSInst, error) {
	if vcf.AgentSigningKey == nil {
		return nil, fmt.Errorf("agent_signing_key is required")
	}
	vs := &VSInst{
		log:                  vcf.Log,
		hopCount:             vcf.HopCount,
		visaPushC:            make(chan *vsapi.PollResponse, 128), // Must be large enough to handle a mass revocation event
		grpcCreds:            vcf.Creds,
		mb:                   NewMailbox(vcf.Log),
		reauthBumpTime:       DefaultReauthBumpTime,
		exitC:                make(chan struct{}),
		accessToken:          vcf.AccessToken,
		agentSigningKey:      vcf.AgentSigningKey,
		allowInvalidPeerAddr: vcf.AllowInvalidPeerAddr,
		nodeState:            vcf.Constrainer,
	}
	if vcf.ReauthBumpTimeOverride > 0 {
		vs.reauthBumpTime = vcf.ReauthBumpTimeOverride
	}
	vs.vtable.table = make(map[uint32]*vtableEnt)
	vs.vtable.nextVisaID = minVisaID
	vs.sessions.apiKeys = make(map[string]*PeerRecord)
	vs.sessions.hellos = make(map[int32]*HelloRecord)
	vs.agentDB.agents = make(map[netip.Addr]*HostRecord)

	nopol := policy.NewEmptyPolicy()
	vs.plcy.p = nopol
	vs.plcy.cid = policy.InitialConfiguration
	if m, err := policy.NewMatcher(nopol.ExportBundle(), policy.InitialConfiguration, vcf.Log); err != nil {
		return nil, err
	} else {
		vs.plcy.matcher = m
	}
	vs.log.Info("visa service instance configured", "reauthBumpTime", vs.reauthBumpTime.String())
	return vs, nil
}

func (vs *VSInst) SetAuthSvc(a auth.AuthService) {
	vs.authr = a
	vs.attrProx = NewAttrProxy(a)
}

// SetLocalAddr sets this visa services local address. Called automatically when Start is called.
// Exposed here for unit tests.
//
// For now this better be the hard coded, static visa service address.
func (vs *VSInst) SetLocalAddr(a netip.Addr) {
	vs.localAddr = a
	vs.nodeNumber = a.As16()[15]
}

// Start is blocking call to start the visa service GRPC listener.
// Also sets this visa services local address.
func (vs *VSInst) Start(listenAddr netip.Addr, port uint16) error {

	vlog, err := NewVlogToFile("visa.log")
	if err != nil {
		return fmt.Errorf("failed to create visa log: %w", err)
	}
	vs.vlog = vlog
	defer vlog.Close()

	vs.grpcWg.Add(1)
	defer vs.grpcWg.Done()
	defer close(vs.exitC)
	thrift.ServerStopTimeout = 5 * time.Second // TODO: Should come from config
	if err := vs.startThriftBlocking(listenAddr, port); err != nil {
		vs.log.WithError(err).Error("visa service start failed")
		return fmt.Errorf("failed to start visa service: %w", err)
	}
	return nil
}

func (vs *VSInst) Stop() {
	vs.thriftServer.Stop()
}

func (vs *VSInst) HasPollerNode(nodeAddr netip.Addr) bool {
	return vs.mb.HasPoller(nodeAddr.String())
}

func (vs *VSInst) HasRegisteredNode(nodeAddr netip.Addr) bool {
	vs.sessions.RLock()
	defer vs.sessions.RUnlock()
	for _, pr := range vs.sessions.apiKeys {
		if nodeAddr == pr.ZPRAddr {
			return true
		}
	}
	return false
}

// Implement policy.Configurator interface.
// TODO: Pretty sure this is irrelevant for the visa service.  Was (is?) used to alter some configuration values
// on a node.  For now logging when this is used to see if we need it.
func (vs *VSInst) SetConfig(key, value string) error {
	vs.log.Info("XXX ==configurator== SET_CONFIG (NOP!!) >>", "key", key, "value", value)
	return nil
}

// runloop is normally started as side-effect of starting the grpc server, via the Start
// function.
func (vs *VSInst) runloop(exitC chan struct{}) error {
	tkr := time.NewTicker(15 * time.Second)
	defer tkr.Stop()

VS_RUNLOOP:
	for {
		select {

		case <-exitC:
			break VS_RUNLOOP

		case now := <-tkr.C:
			vs.periodicHousekeeping(now)

		case req, ok := <-vs.visaPushC: // Drain this push channel
			// TODO: This is not a great plan. These boxes for the docks and forwarders could get large.
			//       Also, polling is not a good fit for the revoke use-case. In that case we want to
			//       kill the visa/credential immediately.
			if ok {
				vs.mb.AppendMessage(req)
			}

		case <-vs.exitC:
			break VS_RUNLOOP
		}
	}
	vs.log.Info("runloop exits")
	return nil
}

// periodicHousekeeping is called from runloop (and so blocks runloop).
func (vs *VSInst) periodicHousekeeping(now time.Time) {
	vs.extendVisaServiceVisas()
	vs.removeExpiredVisas()
	vs.expireOldConfiguration()
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
			remain := time.Until(vsio.VToTime(ve.v.GetExpires()))
			if remain < VSVisaRenewalTime {
				sourceAddr, _ := netip.AddrFromSlice(ve.v.Source)
				agnt, err := vs.AgentAtContactAddr(sourceAddr) // for a node contact_addr is visa "tether" addr.
				if err != nil || agnt == nil {
					continue // agent is gone
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

// renewEssentialVisasForCurrentConfig renews the visa-service visas found in our
// store if they are not already on the current net-config.
func (vs *VSInst) renewEssentialVisasForCurrentConfig(configID, policyID uint64) {
	var oldVisas []*vtableEnt

	vs.vtable.mtx.RLock()
	for _, ve := range vs.vtable.table {
		if ve.isVSVisa {
			if ve.v.Configuration != configID && ve.successor == 0 {
				oldVisas = append(oldVisas, ve)
			}
		}
	}
	vs.vtable.mtx.RUnlock()
	if sz := len(oldVisas); sz > 0 {
		vs.log.Info("re-requesting essential visas due to config change", "count", sz)
	}
	// Create a new visa with same parameters as original, and push to nodes.
	vs.rerequestVisas(oldVisas, (2 * VSVisaRenewalTime), true, policyID)
}

// rerequestVisas requests "successor" visas for the visas in the passed list.
func (vs *VSInst) rerequestVisas(xvisas []*vtableEnt, minDuration time.Duration, push bool, expectedPolicyID uint64) {
	for _, ve := range xvisas {
		sourceTetherAddr, _ := netip.AddrFromSlice(ve.v.Source)
		resp, err := vs.doRequestVisa(context.Background(), sourceTetherAddr, ve.pktData, minDuration, expectedPolicyID)
		if err != nil {
			vs.log.WithError(err).Error("failed to re-request visa")
		} else {
			vs.vtable.mtx.Lock()
			if rec, ok := vs.vtable.table[ve.v.GetIssuerId()]; ok {
				rec.successor = uint32(resp.Visa.IssuerID)
			} else {
				vs.log.Error("failed to locate predecessor visa in table", "issuerID", ve.v.GetIssuerId())
			}
			// vs.dumpVisaTableHoldingLock("rerequest")
			vs.vtable.mtx.Unlock()
			if push {
				vs.mb.AppendVisaResponseMessage(resp)
			}
		}
	}
}

func (vs *VSInst) removeExpiredVisas() {
	vs.vtable.mtx.Lock()
	defer vs.vtable.mtx.Unlock()
	curTS := vsio.VTimeNow()
	for vid, vv := range vs.vtable.table {
		if curTS > vv.v.GetExpires() {
			vs.log.Info("visa has expired", "visaID", vid)
			delete(vs.vtable.table, vid)
		}
	}
	// vs.dumpVisaTableHoldingLock("removeExpired")
}

// Push the visa for polling nodes.
//
// TODO: Presumably the mailbox system makes sure the right visa goes to the right node?
//
// Note blocks if our push channel is full.
func (vs *VSInst) PushVisa(pr *vsapi.PollResponse) {
	vs.visaPushC <- pr
}

// expireAllVisas is called when policy is updated.  Revokes and removes all visas under the
// given network configuration.
func (vs *VSInst) expireAllVisas(config uint64) {
	vs.vtable.mtx.Lock()
	defer vs.vtable.mtx.Unlock()
	count := 0
	for vID, ve := range vs.vtable.table {
		if ve.v.Configuration == config {
			revoke := &vsapi.PollResponse{
				Revocations: []*vsapi.VisaRevocation{
					{
						IssuerID:      int32(vID),
						Configuration: int64(config),
					},
				},
			}

			// We are often called from runloop so blocking here would be bad.
			select {
			case vs.visaPushC <- revoke: // ok
			default:
				vs.log.Warn("push channel full, failed to issue revoke, continuing")
			}
			delete(vs.vtable.table, vID)
			count++
		}
	}
	vs.log.Infof("%d visas revoked due to configuration change", count)
}

// RequestVisa perform a visa request operation.
// Set `minDuration` to force a minimum TTL on the visa, or set to 0 to leave
// calculated expiration value alone.
//
// TODO: We do not pay attention to the context. If the context expires the
//
//	caller (dock, for example) will ignore the response.
func (vs *VSInst) doRequestVisa(ctx context.Context, tetherAddr netip.Addr, pktData *snip.Traffic, minDuration time.Duration, expectedPolicyID uint64) (*vsapi.VisaResponse, error) {
	// Packet will either be an opening request of a client to a service, or a response
	// from a service to a client.  The addresses in the packet will be contact addresses.
	//
	// We need to see if there is any policy on file that permits this communication and if so, issue a visa.
	//
	// The visa will be expressed in tether addresses. But the PEP args will include contact addresses.
	//

	vs.log.Debug("RequestVisa starts", "zprSRC", pktData.SrcAddr, "zprDEST", pktData.DstAddr, "dport", pktData.DstPort)

	curpol, curmatcher, curConfigID := vs.getPolicyMatcherConfig()
	if curpol == nil || curmatcher == nil || curpol.IsEmpty() {
		vs.log.Info("visa denied: nil or empty policy", "source", pktData.SrcAddr)
		return nil, ErrDeniedByPolicy
	}
	if curpol.VersionNumber() != expectedPolicyID {
		vs.log.Info("visa denied: version mismatch", "found", curpol.VersionNumber(), "expected", expectedPolicyID)
		return nil, ErrVSMisconfigure
	}

	srcAgent, dstAgent, err := vs.endpointsForTraffic(pktData)
	if err != nil {
		return nil, err
	}

	// Do not issue a visa if either of the agents has expired.
	//
	// Note that we allow the expiration to be ZERO to handle case where we are
	// talking about the nodes internal tunnel.  Possibly it would be better to
	// actually set an expire time out our internal tunnel.  In any case I could
	// see wanting to actually re-auth the internal tunnel, in case data source
	// values have changed, for example.
	srcAgentExpire, dstAgentExpire := srcAgent.GetAuthExpires(), dstAgent.GetAuthExpires()
	{
		now := time.Now()
		if (!srcAgentExpire.IsZero()) && now.After(srcAgentExpire) {
			vs.log.Info("visa denied, source agent auth has expired")
			return nil, ErrAuthExpired
		}
		if (!dstAgentExpire.IsZero()) && now.After(dstAgentExpire) {
			vs.log.Info("visa denied, dest agent auth has expired")
			return nil, ErrAuthExpired
		}
	}

	dstTether := dstAgent.GetTetherAddr() // The source tether address is in passed in.
	if !dstTether.IsValid() {
		vs.log.Info("destination tether is nil, visa request denied")
		return nil, ErrNoRouteToHost
	}

	if len(dstAgent.GetProvides())+len(srcAgent.GetProvides()) == 0 {
		vs.log.Info("visa denied: no services offered on either endpoint")
		return nil, ErrDeniedByPolicy
	}

	// See if the traffic matches a policy.  Note that the policy has many scopes.
	// If it is ok, create a DOCK PEP and VISA that can be used to forward traffic like it.
	//
	// TODO: One problem with the current matching method is that it requires the full list of
	//       agent attributes.  I shouldn't have to send those between visa services.  A visa
	//       service can query the data sources directly for attrs.  But we do need a way to
	//       identify agents between visa servics.  So if agentX connects at nodeY, when nodeZ
	//       wants to request a visa, it needs to know it is talking about agentX.
	//
	//       Ah ha, maybe just share the agent IDENTITY credentials.  Those the the keys in the
	//       new datasource API anyway.
	//
	now := time.Now()
	{
		updated, newAttrs, err := vs.checkAndUpdateAttrs(now, srcAgent)
		if updated {
			vs.log.Debug("found updates to source authed claims", "agent_addr", srcAgent.GetZPRIDIfSet(), "newAttrs", newAttrs)
			srcAgent.SetAuthedClaims(newAttrs)
		}
		if err != nil {
			if errors.Is(err, auth.ErrNotSupported) {
				vs.log.Info("attribute query not supported for source agent", "agent", srcAgent.GetIdentity())
			} else {
				vs.log.WithError(err).Warn("attribute query failed for source agent", "agent", srcAgent.GetIdentity())
			}
		}
	}
	{
		updated, newAttrs, err := vs.checkAndUpdateAttrs(now, dstAgent)
		if updated {
			vs.log.Debug("found updates to dest authed claims", "agent_addr", srcAgent.GetZPRIDIfSet(), "newAttrs", newAttrs)
			dstAgent.SetAuthedClaims(newAttrs)
		}
		if err != nil {
			if errors.Is(err, auth.ErrNotSupported) {
				vs.log.Info("attribute query not supported for dest agent", "agent", srcAgent.GetIdentity())
			} else {
				vs.log.WithError(err).Warn("attribute query failed for dest agent", "agent", dstAgent.GetIdentity())
			}
		}
	}

	mtSrc, mtDst := policyAgentInfoFromAgent(srcAgent), policyAgentInfoFromAgent(dstAgent)
	cpols, err := curmatcher.MatchTraffic(pktData, mtSrc, mtDst)
	if err != nil {
		vs.visaDenied(curConfigID, "no match", pktData, tetherAddr)
		vs.log.WithError(err).Info("visa denied: match failed")
		return nil, ErrDeniedByPolicy
	}

	// We set a temporary ID on it, giving it a final ID when we add it into our table.
	builder := libvisa.NewVisaBuilder(curConfigID, tetherAddr, dstTether).WithIssuerID(1).
		WithTrafficAndPolicy(pktData, cpols).
		WithDatacapComputeFunc(vs.dataCapApply)

	if cpols[0].FWD {
		builder.WithClientAgentIdent(srcAgent.GetIdentity())
	} else {
		builder.WithClientAgentIdent(dstAgent.GetIdentity())
	}

	// In order to compute expiration I need two things from the visaConfig:
	//  1. The Lifetime value (if any -- this is from a duration constraint)
	//  2. The Cap "period" - a time.Duration
	//
	durationCons := libvisa.MaxDurationConstraintFromPolicies(cpols)

	// For a given set of polcies there may be a single DataCap that applies.
	// If so, grab the period from that datacap to use in our expiration calculations.
	var dataCapPeriod time.Duration
	if cap := libvisa.MaximalDataCapFromPolicies(cpols); cap != nil {
		dataCapPeriod = cap.CapPeriod
	}

	// visaExpiration, expFlags := vs.computeVisaExpiration(curpol.GetMaxVisaLifetime(), visaConfig, srcAgentExpire, dstAgentExpire)
	visaExpiration, expFlags := vs.computeVisaExpiration(curpol.GetMaxVisaLifetime(), durationCons, dataCapPeriod, srcAgentExpire, dstAgentExpire)
	if (minDuration > 0) && time.Until(visaExpiration) < minDuration {
		visaExpiration = time.Now().Add(minDuration)
		expFlags |= libvisa.ExpFMinDur
	}

	// What do we do here?
	if time.Now().After(visaExpiration) {
		return nil, fmt.Errorf("unable to compute valid expiration (%v)", visaExpiration)
	}

	builder = builder.WithExpiration(visaExpiration)

	sKey := make([]byte, 16)
	snauth.NewNonce(sKey)
	builder = builder.WithSessionKeyAndEncoding(sKey, libvisa.SKEv1)

	visa, err := builder.Visa()
	if err != nil {
		return nil, fmt.Errorf("failed to create visa: %w", err)
	}

	// The visa service keeps track of all visas outstanding. Before returning this visa we insert it
	// into our visa table, which generates an ID as a side effect.
	isVSVisa := (vs.localAddr == pktData.DstAddr) && (VisaServicePort == pktData.DstPort)

	vent, err := vs.insertVisaWithNewID(visa, isVSVisa, pktData)
	if err != nil {
		return nil, fmt.Errorf("failed to insert visa into table: %w", err)
	}

	// TODO: Sign visa

	resp := new(vsapi.VisaResponse)
	resp.Status = vsapi.StatusCode_SUCCESS

	pbuf, err := proto.Marshal(vent.v)
	if err != nil {
		vs.log.WithError(err).Error("failed to marshal visa for mailbox")
		return nil, fmt.Errorf("internal error")
	}
	resp.Visa = &vsapi.VisaHop{
		VisaPb:   pbuf,
		HopCount: int32(vs.hopCount),
		IssuerID: int32(vent.v.IssuerId),
	}

	vs.visaCreated(vent.v, visaExpiration, pktData, expFlags.String(), tetherAddr)
	if time.Until(visaExpiration) < (30 * time.Second) {
		vs.log.Warn("visa with very short TTL", "visaID", vent.v.IssuerId, "TTL", time.Until(visaExpiration).String())
	}
	return resp, nil
}

// Urg, so many types!!
func policyAgentInfoFromAgent(agnt *agent.Agent) *policy.AgentInfo {
	aa := &policy.AgentInfo{
		AgentAttrs:    make(map[string]*agent.ClaimV),
		AgentProvides: agnt.GetProvides(),
	}
	for key, claim := range agnt.GetAuthedClaims() {
		aa.AgentAttrs[key] = claim
	}
	return aa
}

// dataCapApply will track the application of a (possibly grouped) data cap.
// Returns the key under which the DataCap is stored, and the amount of data (in bytes) remaining.
//
// This matches the interface require by the libvisa builder.
//
// TODO: Not sure how to safely clean out cap table.
func (vs *VSInst) dataCapApply(fwd bool, cap *libvisa.DataCap, clientAgentIdent string) (capKey string, remain uint64, err error) {
	capID := cap.SvcID
	if cap.CapGroup != "" {
		capID = cap.CapGroup
	}
	capVal := fmt.Sprintf("%v/%v", cap.CapBytes, cap.CapPeriod.String())

	// Create and md5 hex value from the parts. Note FWD and REV get different keys
	// `fwd` TRUE if forward visa
	// `agent` Identify agent (regardless of dock)
	// `capID` Either the service or the group name
	// `capVal` Expression of the value "amount for period"
	capKey = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%v_%v_%v_%v", fwd, clientAgentIdent, capID, capVal))))

	vs.log.Debug("new data cap constraint", "capKey", capKey, "FWD", fwd, "ident", clientAgentIdent, "capID", capID)
	rCons := vs.nodeState.ConstraintByKey(capKey)
	if rCons == nil {
		vs.nodeState.ProposeConstraint(&RConstraint{
			Key:           capKey,
			CapBytes:      cap.CapBytes,
			PeriodSeconds: uint64(cap.CapPeriod / time.Second),
			PeriodStarts:  uint64(time.Now().Unix()),
		})
		// TODO: We should wait for raft to accept the proposal.
		remain = cap.CapBytes
	} else {
		// Found!
		vs.log.Debug("data cap found", "remain", rCons.GetCapBytes())
		pStart := time.Unix(int64(rCons.GetPeriodStarts()), 0)
		if time.Since(pStart) > (time.Duration(rCons.PeriodSeconds) * time.Second) {
			// period elapsed.
			rCons.Consumed = 0
			rCons.PeriodStarts = uint64(time.Now().Unix())
			remain = rCons.GetCapBytes() // and so full capacity is available.
			vs.nodeState.ProposeConstraint(rCons)
		} else {
			// still within a period
			if rCons.Consumed >= rCons.CapBytes {
				remain = 0
			} else {
				remain = rCons.CapBytes - rCons.Consumed
			}
		}
	}
	return
}

// ReportVisaStats is called by Docks (and forwarders?) to update visa usage details.
func (vs *VSInst) reportVisaStats(vid uint32, capKey string, bytesUsed uint64) {
	// Is it possible visa is removed before we get this message? Definitely.
	vs.log.Info("visa stats", "visaID", vid, "bytesUsed", bytesUsed, "key", capKey) // TODO: add to accounting log.
	if capKey != "" && bytesUsed > 0 {
		if rCons := vs.nodeState.ConstraintByKey(capKey); rCons != nil {
			// Update bytes used.
			pStart := time.Unix(int64(rCons.GetPeriodStarts()), 0)
			if time.Since(pStart) > (time.Duration(rCons.PeriodSeconds) * time.Second) {
				// period elapsed.
				rCons.Consumed = bytesUsed
				rCons.PeriodStarts = uint64(time.Now().Unix())
			} else {
				// Within period
				rCons.Consumed += bytesUsed
			}
			vs.nodeState.ProposeConstraint(rCons)
		} else {
			vs.log.Info("stats for unknown capKey, ignoring", "key", capKey)
		}
	}
}

// Visa will expire at the soonest of:
//   - the agent credentials (in play) expire - (we actually just consider all creds the agent is using)
//   - the max lifetime set in policy
//   - the duration constraint set by the PEP in VConfig
//   - end of datacap period, if applicable
//
// Note this assumes that caller has already checked the agent auth expirations.
//
// Also returns an explanation bitfield which indicates how the expiration was
// computed.
func (vs *VSInst) computeVisaExpiration(maxVisaLifetime time.Duration, durationCons, datacapPeriod time.Duration, srcAuthExp, dstAuthExp time.Time) (time.Time, libvisa.ExpFlag) {
	var flags libvisa.ExpFlag
	var exp time.Time
	now := time.Now()
	srcAuthOK := (!srcAuthExp.IsZero()) && srcAuthExp.After(now)
	dstAuthOK := (!dstAuthExp.IsZero()) && dstAuthExp.After(now)
	if srcAuthOK {
		if dstAuthOK && dstAuthExp.Before(srcAuthExp) {
			exp = dstAuthExp.Add(vs.reauthBumpTime) // give time for creds re-auth
			flags |= libvisa.ExpFDestCreds | libvisa.ExpFBump
		} else {
			exp = srcAuthExp.Add(vs.reauthBumpTime) // give time for creds re-auth
			flags |= libvisa.ExpFSrcCreds | libvisa.ExpFBump
		}
	} else if dstAuthOK {
		exp = dstAuthExp.Add(vs.reauthBumpTime) // give time for creds re-auth
		flags |= libvisa.ExpFDestCreds | libvisa.ExpFBump
	}
	if polExpiration := now.Add(maxVisaLifetime); exp.IsZero() || polExpiration.Before(exp) {
		// Try using maxVisaLifetime (comes from policy global setting)
		exp = polExpiration
		flags |= libvisa.ExpFMaxLifetime
	}
	if durationCons > 0 {
		// If there is a duration constraint on the specific policy, try that.
		if pepEx := time.Now().Add(durationCons); exp.IsZero() || pepEx.Before(exp) {
			exp = pepEx
			flags |= libvisa.ExpFPolicy
		}
	}
	if datacapPeriod > 0 {
		// If there is a data cap then that will be added to the visa. The cap only applies during the period, so
		// the visa must expire within the period.
		if capExp := time.Now().Add(datacapPeriod); exp.IsZero() || capExp.Before(exp) {
			exp = capExp
			flags |= libvisa.ExpFDataCap
		}
	}
	if time.Until(exp) > (35 * time.Minute) {
		// Add some jitter so that all the visas do not bunch up
		exp = exp.Add(time.Duration(-1*rand.Intn(30)) * time.Minute)
		flags |= libvisa.ExpFJitter
	}
	return exp, flags
}

// endpointsForTraffic locate the source and destination agents by using the directory
// to see what agent is connected at each endpoint.
func (vs *VSInst) endpointsForTraffic(pktData *snip.Traffic) (srcAgent *agent.Agent, dstAgent *agent.Agent, err error) {
	// Note that the visa service does not check for a route. The existence of an entry in the DirectoryService implies a route.
	srcAgent, err = vs.AgentAtContactAddr(pktData.SrcAddr)
	if err != nil {
		vs.log.WithError(err).Info("visa denied: failed to resolve source ZPR address", "source", pktData.SrcAddr)
		return nil, nil, ErrNoRouteToHost
	}
	dstAgent, err = vs.AgentAtContactAddr(pktData.DstAddr)
	if err != nil {
		vs.log.WithError(err).Info("visa denied: failed to resolve dest ZPR address", "dest", pktData.DstAddr)
		return nil, nil, ErrNoRouteToHost
	}
	return
}

// inserVisaWithNewID first creates a new visa ID (based on our visa prefix, which is based on our node name),
// then it updates the visaID field on the passed visa, and inserts the visa into our table.
func (vs *VSInst) insertVisaWithNewID(v *vsio.Visa, isVSVisa bool, pktData *snip.Traffic) (*vtableEnt, error) {
	vs.vtable.mtx.Lock()

	// always increasing.
	vID := vs.vtable.nextVisaID
	if vID > maxVisaID {
		panic(fmt.Sprintf("max visa ID reached: %d", vID)) // TODO: solve this :)
	}
	vs.vtable.nextVisaID = vID + 1
	v.IssuerId = (uint32(vs.nodeNumber) << 24) | vID
	ve := &vtableEnt{
		v:        v,
		isVSVisa: isVSVisa,
		pktData:  pktData,
	}
	vs.vtable.table[v.IssuerId] = ve
	sz := len(vs.vtable.table)
	// vs.dumpVisaTableHoldingLock("insertVisa")
	vs.vtable.mtx.Unlock()
	vs.log.Debug("added visa", "id", vID, "isVsVisa?", isVSVisa, "netconfig", v.Configuration, "tableSize", sz)
	return ve, nil
}

func (vs *VSInst) visaDenied(configID uint64, reason string, pktData *snip.Traffic, tetherAddr netip.Addr) {
	if vs.vlog != nil {
		vs.vlog.LogVisaDenied(configID, pktData, reason, tetherAddr)
	}
	vs.log.Info("Visa denied", "flow", pktData.Flow(), "reason", reason)
}

func (vs *VSInst) visaCreated(visa *vsio.Visa, expires time.Time, pktData *snip.Traffic, explainer string, requestor netip.Addr) {
	if vs.vlog != nil {
		vs.vlog.LogVisaCreated(visa, pktData, explainer, requestor)
	}
	vs.log.Info("visa created", "flow", pktData.Flow(), "explain", explainer, "configuration", visa.Configuration, "expires", expires)
}

// checkAndUpdateAttrs given an agent identity set and a set of auth'd attributes, first check
// to see if any of the attributes has expired. If so run a query against the datasources
// for updated values. The query hits our proxy/cache so may or many not actually have
// to go all the way to the datasources.
//
// Note that expired claimes are removed from the returned set of attributes. Even if
// the query to refresh them fails.
//
// Returns (ATTRS_CHANGED_FLAG, NEW_ATTRS, ERROR)
//
// If ATTRS_CHANGED_FLAG is true then the NEW_ATTRS should replace the ones on the
// passed agent -- even if an error is indicated.
//
// ErrNotSupported is returned as error in case where the data source does not support
// the Query operation.  (PROBLEM: what if there are multiple data sources?)
func (vs *VSInst) checkAndUpdateAttrs(now time.Time, agnt *agent.Agent) (bool, map[string]*agent.ClaimV, error) {

	keepAttrs := make(map[string]*agent.ClaimV)

	var expired []string // we query for these

	for aKey, aVx := range agnt.GetAuthedClaims() {
		if strings.HasPrefix(aKey, "zpr.") {
			keepAttrs[aKey] = aVx
			continue // For now we don't know how to update zpr keys
		}
		if aVx.Exp.IsZero() {
			keepAttrs[aKey] = aVx
			continue // unset? Then it never expires.
		}
		if now.After(aVx.Exp) {
			expired = append(expired, aKey)
		} else {
			keepAttrs[aKey] = aVx
		}
	}
	if len(expired) == 0 {
		return false, agnt.GetAuthedClaims(), nil // no changes, nothing expired.
	}

	var toks [][]byte
	toks = append(toks, []byte(agnt.GetIdentity())) // TODO: what if there are multiple tokens on an agent?
	qreq := &zds.QueryRequest{
		TokenList: toks,
		AttrKeys:  expired,
	}
	// Note that the keys have datasource prefixes on them.
	// The auth service will set the prefixes on the response too
	qresp, err := vs.attrProx.Query(now, qreq)
	if err != nil {
		// TODO: If datasource does not support query (eg, internal DS), should we
		//       still remove the "expired" claims?  What is caller supposed to do?
		//       How does caller detect when it needs to re-auth instead?
		//
		// FOR NOW WE ARE REMOVING EXPIRED CLAIMS !!
		return true, keepAttrs, err
	}
	// Proxy may use the ttl on the response, but we do not care.
	for _, za := range qresp.Attrs {
		// Make sure source does not try to set any zpr keys!
		if strings.HasPrefix(za.Key, "zpr.") {
			vs.log.Info("invalid attempt by trusted service to set zpr key", "key", za.Key, "value", za.Val)
			continue
		}
		keepAttrs[za.Key] = &agent.ClaimV{
			V:   za.Val,
			Exp: time.Unix(za.Exp, 0),
		}
	}
	return true, keepAttrs, nil // No error, and attributes have been updated
}

// For debugging assistance only
func (vs *VSInst) dumpVisaTableHoldingLock(reason string) {
	vs.log.Infof("xxx starting table dump (%v) %d entries xxx", reason, len(vs.vtable.table))
	for vid, ent := range vs.vtable.table {
		vs.log.Info("__entry__",
			"issuerID", vid,
			"flow", ent.pktData.Flow(),
			"duration", time.Until(vsio.VToTime(ent.v.Expires)).String(),
			"successor", ent.successor)
	}
	vs.log.Info("xxx table dump ends xxx")
}

package vservice

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"time"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/tsapi"
	"zpr.org/vs/pkg/vservice/adb"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"
)

// renewEssentialVisasForCurrentConfig renews the visa-service visas found in our
// store if they are not already on the current net-config.
func (vs *VSInst) renewEssentialVisasForCurrentConfig(configID, policyID uint64) {
	var oldVisas []*vtableEnt

	configIDi64 := int64(configID)

	vs.vtable.mtx.RLock()
	for _, ve := range vs.vtable.table {
		if ve.isVSVisa {
			if ve.v.Configuration != configIDi64 && ve.successor == 0 {
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

	srcActor, dstActor := vs.endpointsForTraffic(pktData)
	if srcActor == nil && dstActor == nil {
		vs.log.Info("visa denied: failed to resolve source and dest ZPR addresss", "source", pktData.SrcAddr, "dest", pktData.DstAddr)
		vs.actorDB.Dump(vs.log) // For help debugging endpoint not found
		return nil, ErrNoRouteToHost
	}
	if srcActor == nil || dstActor == nil {
		// HACK: Until the node sends us a connect message when an actor connects
		// but before they authenticate we have no knowledge of the that is about to
		// try authenticating.  So for now we override policy and will allow any
		// actor to talk to an installed authentication service.
		var candidate *actor.Actor
		var anonAddr netip.Addr
		if srcActor == nil {
			candidate = dstActor
			anonAddr = pktData.SrcAddr
		} else {
			candidate = srcActor
			anonAddr = pktData.DstAddr
		}
		var matchedSvc string
		for _, sname := range curpol.GetActorAuthenticationServiceNames() {
			if slices.Contains(candidate.GetProvides(), sname) {
				vs.log.Info("allowing visa request from anon to auth service, overriding policy", "service", sname)
				matchedSvc = sname
				break
			}
		}
		if matchedSvc == "" {
			if srcActor == nil {
				vs.log.Info("visa denied: failed to resolve source ZPR addresss", "source", pktData.SrcAddr)
			} else {
				vs.log.Info("visa denied: failed to resolve dest ZPR addresss", "dest", pktData.DstAddr)
			}
			return nil, ErrNoRouteToHost // oh well, we tried.
		}
		// Now we fabricate an anon actor for this visa.
		expiration := time.Now().Add(5 * time.Minute)
		anonActor := actor.EmptyActor()
		claims := make(map[string]*actor.ClaimV)
		claims[actor.KAttrEPID] = actor.NewClaimV(anonAddr.String(), expiration)
		claims[actor.KAttrAuthority] = actor.NewClaimV("vs_hack_anon_to_auth", expiration)
		claims[actor.KAttrRole] = actor.NewClaimV("adapter", expiration)
		claims[actor.KAttrCN] = actor.NewClaimV(fmt.Sprintf("hack.%s.zpr", anonAddr), expiration)
		anonActor.SetAuthenticated(claims, expiration, nil, nil, curConfigID)
		if srcActor == nil {
			srcActor = anonActor
		} else {
			dstActor = anonActor
		}
		vs.log.Debug("HACK: created anonymous actor for auth service", "actor", anonActor.String(), "service", matchedSvc)
	}

	// Do not issue a visa if either of the actors has expired.
	//
	// Note that we allow the expiration to be ZERO to handle case where we are
	// talking about the nodes internal tunnel.  Possibly it would be better to
	// actually set an expire time out our internal tunnel.  In any case I could
	// see wanting to actually re-auth the internal tunnel, in case data source
	// values have changed, for example.
	srcActorExpire, dstActorExpire := srcActor.GetAuthExpires(), dstActor.GetAuthExpires()
	{
		now := time.Now()
		if (!srcActorExpire.IsZero()) && now.After(srcActorExpire) {
			vs.log.Info("visa denied, source actor auth has expired")
			return nil, ErrAuthExpired
		}
		if (!dstActorExpire.IsZero()) && now.After(dstActorExpire) {
			vs.log.Info("visa denied, dest actor auth has expired")
			return nil, ErrAuthExpired
		}
	}

	dstTether := dstActor.GetTetherAddr() // The source tether address is in passed in.
	if !dstTether.IsValid() {
		vs.log.Info("destination tether is nil, visa request denied")
		return nil, ErrNoRouteToHost
	}

	if len(dstActor.GetProvides())+len(srcActor.GetProvides()) == 0 {
		vs.log.Info("visa denied: no services offered on either endpoint")
		return nil, ErrDeniedByPolicy
	}

	// See if the traffic matches a policy.  Note that the policy has many scopes.
	// If it is ok, create a DOCK PEP and VISA that can be used to forward traffic like it.
	//
	// TODO: One problem with the current matching method is that it requires the full list of
	//       actor attributes.  I shouldn't have to send those between visa services.  A visa
	//       service can query the data sources directly for attrs.  But we do need a way to
	//       identify actors between visa servics.  So if actorX connects at nodeY, when nodeZ
	//       wants to request a visa, it needs to know it is talking about actorX.
	//
	//       Ah ha, maybe just share the actor IDENTITY credentials.  Those the the keys in the
	//       new datasource API anyway.
	//
	now := time.Now()
	{
		updated, newAttrs, err := vs.checkAndUpdateAttrs(now, srcActor)
		if updated {
			vs.log.Debug("found updates to source authed claims", "actor_addr", srcActor.GetZPRIDIfSet(), "newAttrs", newAttrs)
			srcActor.SetAuthedClaims(newAttrs)
		}
		if err != nil {
			if errors.Is(err, auth.ErrNotSupported) {
				vs.log.Info("attribute query not supported for source actor", "actor", srcActor.GetIdentity())
			} else {
				vs.log.WithError(err).Warn("attribute query failed for source actor", "actor", srcActor.GetIdentity())
			}
		}
	}
	{
		updated, newAttrs, err := vs.checkAndUpdateAttrs(now, dstActor)
		if updated {
			vs.log.Debug("found updates to dest authed claims", "actor_addr", srcActor.GetZPRIDIfSet(), "newAttrs", newAttrs)
			dstActor.SetAuthedClaims(newAttrs)
		}
		if err != nil {
			if errors.Is(err, auth.ErrNotSupported) {
				vs.log.Info("attribute query not supported for dest actor", "actor", srcActor.GetIdentity())
			} else {
				vs.log.WithError(err).Warn("attribute query failed for dest actor", "actor", dstActor.GetIdentity())
			}
		}
	}

	mtSrc, mtDst := policyActorInfoFromActor(srcActor), policyActorInfoFromActor(dstActor)
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
		builder.WithClientActorIdent(srcActor.GetIdentity())
	} else {
		builder.WithClientActorIdent(dstActor.GetIdentity())
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

	// visaExpiration, expFlags := vs.computeVisaExpiration(curpol.GetMaxVisaLifetime(), visaConfig, srcActorExpire, dstActorExpire)
	visaExpiration, expFlags := vs.computeVisaExpiration(curpol.GetMaxVisaLifetime(), durationCons, dataCapPeriod, srcActorExpire, dstActorExpire)
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

	resp.Visa = &vsapi.VisaHop{
		Visa:     vent.v,
		HopCount: int32(vs.hopCount),
		IssuerID: vent.v.IssuerID,
	}

	vs.visaCreated(vent.v, visaExpiration, pktData, expFlags.String(), tetherAddr)
	if time.Until(visaExpiration) < (30 * time.Second) {
		vs.log.Warn("visa with very short TTL", "visaID", vent.v.IssuerID, "TTL", time.Until(visaExpiration).String())
	}
	return resp, nil
}

// Urg, so many types!!
func policyActorInfoFromActor(agnt *actor.Actor) *policy.ActorInfo {
	aa := &policy.ActorInfo{
		ActorAttrs:    make(map[string]*actor.ClaimV),
		ActorProvides: agnt.GetProvides(),
	}
	for key, claim := range agnt.GetAuthedClaims() {
		aa.ActorAttrs[key] = claim
	}
	return aa
}

// dataCapApply will track the application of a (possibly grouped) data cap.
// Returns the key under which the DataCap is stored, and the amount of data (in bytes) remaining.
//
// This matches the interface require by the libvisa builder.
//
// TODO: Not sure how to safely clean out cap table.
func (vs *VSInst) dataCapApply(fwd bool, cap *libvisa.DataCap, clientActorIdent string) (capKey string, remain uint64, err error) {
	capID := cap.SvcID
	if cap.CapGroup != "" {
		capID = cap.CapGroup
	}
	capVal := fmt.Sprintf("%v/%v", cap.CapBytes, cap.CapPeriod.String())

	// Create and md5 hex value from the parts. Note FWD and REV get different keys
	// `fwd` TRUE if forward visa
	// `actor` Identify actor (regardless of dock)
	// `capID` Either the service or the group name
	// `capVal` Expression of the value "amount for period"
	capKey = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%v_%v_%v_%v", fwd, clientActorIdent, capID, capVal))))

	vs.log.Debug("new data cap constraint", "capKey", capKey, "FWD", fwd, "ident", clientActorIdent, "capID", capID)
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

// Visa will expire at the soonest of:
//   - the actor credentials (in play) expire - (we actually just consider all creds the actor is using)
//   - the max lifetime set in policy
//   - the duration constraint set by the PEP in VConfig
//   - end of datacap period, if applicable
//
// Note this assumes that caller has already checked the actor auth expirations.
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

// endpointsForTraffic locate the source and destination actors by using the directory
// to see what actor is connected at each endpoint.
//
// If we cannot find the actor in our actor database a nil entry is returned.
func (vs *VSInst) endpointsForTraffic(pktData *snip.Traffic) (srcActor *actor.Actor, dstActor *actor.Actor) {
	// Note that the visa service does not check for a route. The existence of an entry in the DirectoryService implies a route.
	srcActor, _ = vs.actorDB.ActorAtContactAddr(pktData.SrcAddr)
	dstActor, _ = vs.actorDB.ActorAtContactAddr(pktData.DstAddr)
	return
}

// inserVisaWithNewID first creates a new visa ID (based on our visa prefix, which is based on our node name),
// then it updates the visaID field on the passed visa, and inserts the visa into our table.
func (vs *VSInst) insertVisaWithNewID(v *vsapi.Visa, isVSVisa bool, pktData *snip.Traffic) (*vtableEnt, error) {
	vs.vtable.mtx.Lock()

	// always increasing.
	vID := vs.vtable.nextVisaID
	if vID > maxVisaID {
		panic(fmt.Sprintf("max visa ID reached: %d", vID)) // TODO: solve this :)
	}
	vs.vtable.nextVisaID = vID + 1
	v.IssuerID = int32(((uint32(vs.nodeNumber) << 24) | vID) & 0x7FFFFFFF)
	ve := &vtableEnt{
		v:        v,
		isVSVisa: isVSVisa,
		pktData:  pktData,
	}
	vs.vtable.table[uint32(v.IssuerID)] = ve
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

func (vs *VSInst) visaCreated(visa *vsapi.Visa, expires time.Time, pktData *snip.Traffic, explainer string, requestor netip.Addr) {
	if vs.vlog != nil {
		vs.vlog.LogVisaCreated(visa, pktData, explainer, requestor)
	}
	vs.log.Info("visa created", "flow", pktData.Flow(), "explain", explainer, "configuration", visa.Configuration, "expires", expires)
}

// checkAndUpdateAttrs given an actor identity set and a set of auth'd attributes, first check
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
// passed actor -- even if an error is indicated.
//
// ErrNotSupported is returned as error in case where the data source does not support
// the Query operation.  (PROBLEM: what if there are multiple data sources?)
func (vs *VSInst) checkAndUpdateAttrs(now time.Time, agnt *actor.Actor) (bool, map[string]*actor.ClaimV, error) {

	keepAttrs := make(map[string]*actor.ClaimV)

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
	toks = append(toks, []byte(agnt.GetIdentity())) // TODO: what if there are multiple tokens on an actor?
	qreq := &tsapi.QueryRequest{
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
		keepAttrs[za.Key] = &actor.ClaimV{
			V:   za.Val,
			Exp: time.Unix(za.Exp, 0),
		}
	}
	return true, keepAttrs, nil // No error, and attributes have been updated
}

// Returns ErrVisaNotFound if the visa is not found.
func (vs *VSInst) revokeVisaByID(visaID uint64) error {
	var revokes []*vsapi.VisaRevocation

	vs.vtable.mtx.Lock()
	if ve, ok := vs.vtable.table[uint32(visaID)]; ok {
		delete(vs.vtable.table, uint32(visaID))
		vs.log.Info("visa revoked", "visa_id", visaID)
		revokes = append(revokes, &vsapi.VisaRevocation{
			IssuerID:      int32(visaID),
			Configuration: int64(ve.v.Configuration),
		})
	}
	vs.vtable.mtx.Unlock()

	if len(revokes) == 0 {
		return ErrVisaNotFound
	}
	for _, vr := range revokes {
		vs.vlog.LogVisaRevoked(uint64(vr.IssuerID), uint64(vr.Configuration))
	}
	push := adb.PushItem{
		Broadcast:   true,
		Revocations: revokes,
	}
	select {
	case vs.visaPushC <- &push: // ok
	default:
		vs.log.Warn("push channel full, failed to issue revoke")
		return fmt.Errorf("visa service push channel full")
	}
	return nil
}

// revokeVisasForActors revokes all visas associated with the given actors.
// Returns numbe of visas removed from the table.
func (vs *VSInst) revokeVisasForActors(actors []*actor.Actor) uint32 {
	var count uint32
	var revokes []*vsapi.VisaRevocation

	var addrs []netip.Addr
	for _, agnt := range actors {
		if zprAddr, ok := agnt.GetZPRID(); ok {
			if zprAddr.Is6() {
				addrs = append(addrs, zprAddr)
			} else {
				addrs = append(addrs, netip.AddrFrom16(zprAddr.As16()))
			}
		}
	}
	if len(addrs) == 0 {
		return 0
	}

	visaIDs := vs.visaIDsWithIPv6Addrs(addrs)
	if len(visaIDs) > 0 {
		vs.vtable.mtx.Lock()
		for _, vid := range visaIDs {
			vKey := uint32(vid)
			if ve, ok := vs.vtable.table[vKey]; ok {
				delete(vs.vtable.table, vKey)
				revokes = append(revokes, &vsapi.VisaRevocation{
					IssuerID:      int32(vKey),
					Configuration: int64(ve.v.Configuration),
				})
				count++
			}
		}
		vs.vtable.mtx.Unlock()
	}

	if len(revokes) > 0 {
		push := adb.PushItem{
			Broadcast:   true,
			Revocations: revokes,
		}
		select {
		case vs.visaPushC <- &push: // ok
		default:
			vs.log.Warn("push channel full, failed to issue revoke (FIXME)")
			// TODO: This is a problem. By now visa is removed from visa service but
			//       we were unable to push through the revocation to the node.
		}
	}

	return count
}

// Expensive search of the visa table to find visas that are associated with the
// given addresses.
//
// `addrs` is a list of IPv6 addresses
func (vs *VSInst) visaIDsWithIPv6Addrs(addrs []netip.Addr) []uint64 {
	var visaIDs []uint64

	vs.vtable.mtx.RLock()
Entry:
	for vid, ve := range vs.vtable.table {
		for _, addr := range addrs {
			// TODO: Here I assume that visa source and address are always IPv6
			if bytes.Equal(ve.v.Source, addr.AsSlice()) || bytes.Equal(ve.v.Dest, addr.AsSlice()) {
				visaIDs = append(visaIDs, uint64(vid))
				continue Entry
			}
		}
	}
	vs.vtable.mtx.RUnlock()

	return visaIDs
}

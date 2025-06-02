package policy

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"

	"zpr.org/vsx/polio"
)

var (
	errNoMatch           = errors.New("no matching rule/policy")
	errNoMatchScope      = errors.New("no matching rule on scope")
	errNoMatchConditions = errors.New("no matching rule on conditions")
	errExecFail          = errors.New("no procs ran successfully")
	errUnknownProtocol   = errors.New("unknown protocol")
	errTCPRevSyn         = errors.New("TCP SYN from service")
	errKeyNotClaimed     = errors.New("expression references key with no claimed value")
)

const ScratchValIdx = math.MaxUint32

// matcher for matching policy rules to traffic.
// Three contexts:
// 1) during a connect
// 2) during regular packet traffic, no visa
// 3) during regular packet traffic w/ a visa

type Matcher struct {
	log         logr.Logger
	configID    uint64
	keyMap      map[string]uint32 // attr-key -> key_code
	valMap      map[string]uint32 // attr-value -> val_code
	blankValIdx int
	setIdx      map[uint32][]int // key_code -> list of connect policy (by index) it is in.
	policy      *polio.Policy
	trafficIdx  map[string]map[uint32]map[uint32][]int // SVC_ID -> PROTOCOL -> SVC_PORT -> []POLICY_INDEX
}

type ActorInfo struct {
	ActorAttrs    map[string]*actor.ClaimV // Authed Claims
	ActorProvides []string
}

func (aa *ActorInfo) Provides(svcID string) bool {
	for _, id := range aa.ActorProvides {
		if id == svcID {
			return true
		}
	}
	return false
}

// NewMatcher creates matcher.
func NewMatcher(plcy *polio.Policy, netConfig uint64, log logr.Logger) (*Matcher, error) {
	keyMap := make(map[string]uint32)
	valMap := make(map[string]uint32)

	for i, k := range plcy.GetAttrKeyIndex() {
		if uint32(i) == ScratchValIdx {
			panic("ScratchValIdx must not be used as an attribute key index")
		}
		keyMap[k] = uint32(i)
	}
	for i, v := range plcy.GetAttrValIndex() {
		valMap[v] = uint32(i)
	}

	setIdx := make(map[uint32][]int) // KEYidx -> SET indexes

	for setx, con := range plcy.GetConnects() {
		for _, expr := range con.GetAttrExprs() {
			if sets, ok := setIdx[expr.Key]; !ok {
				setIdx[expr.Key] = []int{setx}
			} else {
				included := false
				for _, j := range sets {
					if j == setx {
						included = true
						break
					}
				}
				if !included {
					setIdx[expr.Key] = append(setIdx[expr.Key], setx)
				}
			}
		}
	}
	blankValIdx := -1
	if idx, blankOk := valMap[""]; blankOk {
		blankValIdx = int(idx)
	}

	mm := &Matcher{
		keyMap:      keyMap,
		valMap:      valMap,
		blankValIdx: blankValIdx,
		setIdx:      setIdx,
		log:         log,
		configID:    netConfig,
		policy:      plcy,
		trafficIdx:  make(map[string]map[uint32]map[uint32][]int),
	}
	mm.buildTrafficIndex()
	return mm, nil
}

// matchAttrsToPolicies take a set of authenticated attributes, find any connect policies that
// are matching.  Returns the policies by their index.
func (m *Matcher) matchAttrsToPolicies(authedClaims map[string]*actor.ClaimV) ([]uint32, error) {
	relevantAttrs := make(map[uint32]map[uint32]bool) // key code -> val code -> true

	for agK, agV := range authedClaims {
		attrKeyCode, ok := m.keyMap[agK]
		if !ok {
			// This attribute is not in any connect policy.
			m.log.Debug("[MX] -- irrelevant actor attribute", "key", agK)
			continue
		}
		if _, exists := relevantAttrs[attrKeyCode]; !exists {
			relevantAttrs[attrKeyCode] = make(map[uint32]bool)
		}
		agVElems := strings.Split(strings.TrimSpace(agV.V), ",")
		fromText := ""
		if len(agVElems) > 1 {
			fromText = fmt.Sprintf(" (from %v)", agV.V)
		}
		for _, agVElem := range agVElems {
			attrValCode, ok := m.valMap[agVElem]
			// Issue here is that as soon as you have a blank value anywhere in policy, we have to check all policies.
			if !ok && m.blankValIdx < 0 {
				// This value is not in any connect policy.
				m.log.Debug("[MX] -- irrelevant actor attribute value", "key", agK, "val", agV.V+fromText)
				continue
			}
			if !ok {
				// The attrValCode was not found in the map, and since we are potentially matching on a
				// blank "has" type of expression we need to put something here but it is not a real value.
				// The index we use must not match any valid index in the table.
				attrValCode = ScratchValIdx
			}
			relevantAttrs[attrKeyCode][attrValCode] = true
			m.log.Debug("[MX] -- relevant actor attribute", "key", agK, "val", agV.V+fromText, "keyCode", attrKeyCode, "valCode", attrValCode)
		}
	}

	var matchedPolicies []uint32          // by index
	checkedPolicies := make(map[int]bool) // avoid duplicate work

	for agKC := range relevantAttrs { // For each of the attributes presented by actor...
		setsToCheck, ok := m.setIdx[agKC] // get all connect policies that incorporate this attribute
		if !ok {
			continue
		}

		// Now check each policy, for each policy we must match ALL conditions.
		for _, setx := range setsToCheck {
			if checkedPolicies[setx] {
				continue // already checked
			}
			cpol := m.policy.GetConnects()[setx]
			// All conditions in policy must match: (MULTIPLE matches is ok IFF there are max one proc)
			if polMatch, i, err := matchAttrExprs(cpol.GetAttrExprs(), relevantAttrs, m.blankValIdx); err != nil {
				m.log.Debugf("[MX] -- failed to match claims, expression: %v: %v", formatAttrExpr(m.policy, cpol.GetAttrExprs()[i]), err)
			} else if polMatch {
				matchedPolicies = append(matchedPolicies, uint32(setx))
			}
			checkedPolicies[setx] = true
		}
	}
	return matchedPolicies, nil
}

// matchAttrExprs tells whether or not a list of attribute expressions are all
// satisfied by a collection of authenticated claims. Keys and values are
// represented by uint32 codes. The claims argument must be a mapping of keys
// to sets of claimed values. Claims that match keys with values that have no
// defined codes should be mapped to empty sets. The returned bool is true if
// every expression is satisfied by at least one (key, value set) mapping and
// false otherwise. If false, the returned int is the index of the first
// expression found to evaluate to false. If any expression cannot be evaluated,
// a non-nil error is returned, and the returned int is the index of the
// offending expression.
func matchAttrExprs(exprs []*polio.AttrExpr, claims map[uint32]map[uint32]bool, blankValIdx int) (bool, int, error) {
	for i, expr := range exprs {
		claimedVals, keyDefined := claims[expr.Key]
		if !keyDefined {
			return false, i, errKeyNotClaimed
		}
		switch op := polio.AttrOpT(expr.Op); op {
		case polio.AttrOpT_EQ:
			if len(claimedVals) > 1 {
				return false, i, fmt.Errorf("%q expression evaluated against multivalued (set) claim", formatAttrExprOp(op))
			} else if _, exists := claimedVals[expr.Val]; !exists {
				return false, i, nil
			}
		case polio.AttrOpT_NE:
			if len(claimedVals) > 1 {
				return false, i, fmt.Errorf("%q expression evaluated against multivalued (set) claim", formatAttrExprOp(op))
			} else if _, exists := claimedVals[expr.Val]; exists {
				return false, i, nil
			}
		case polio.AttrOpT_HAS:
			if blankValIdx >= 0 && int(expr.Val) == blankValIdx {
				// This is a test for (<key>, has, "") which means key exists but we don't care about the value.
				// We already know key is there since we got this far, so this is a passing condition.
			} else if _, exists := claimedVals[expr.Val]; !exists {
				return false, i, nil
			}
		case polio.AttrOpT_EXCLUDES:
			if _, exists := claimedVals[expr.Val]; exists {
				return false, i, nil
			}
		default:
			return false, i, fmt.Errorf("invalid expresion operator: %q", formatAttrExprOp(op))
		}
	}
	return true, -1, nil
}

// TODO Do we need this? Isn't the expr debug-logged somewhere already?
// Returns a string representation of an attribute expression in a policy.
func formatAttrExpr(policy *polio.Policy, expr *polio.AttrExpr) string {
	key := policy.GetAttrKeyIndex()[expr.Key]
	op := strings.ToLower(expr.Op.String())
	val := policy.GetAttrValIndex()[expr.Val]
	return fmt.Sprintf("[%s, %s, %s]", key, op, val)
}

// Returns a string representation of a map of claimed attributes.
func formatClaimedAttrs(attrs map[string]*actor.ClaimV) string {
	var buf strings.Builder
	for key, val := range attrs {
		if buf.String() != "" {
			fmt.Fprintf(&buf, ", ")
		}
		fmt.Fprintf(&buf, "(%v, %v)", key, val.V)
	}
	return buf.String()
}

// Returns a string representation of an attribute expression operator
// given its enumeration value.
func formatAttrExprOp(op polio.AttrOpT) string {
	return strings.ToLower(op.String())
}

// getProcsIfNotIn returns the set of connect procs attached to the matched policies
// so long as the proc is NOT already in the list `plist`.
func (m *Matcher) getProcsIfNotIn(matchedPolicies []uint32, plist []uint32) []uint32 {
	var matchedProcs []uint32
	for _, setx := range matchedPolicies {
		cpol := m.policy.GetConnects()[setx]
		if cpol.Proc != NoProc {
			// Keep this proc to run if we don't already have it AND if it has not been run already.
			keep := true
			for _, j := range matchedProcs {
				if j == cpol.Proc {
					keep = false
					break
				}
			}
			if keep {
				for _, k := range plist {
					if k == cpol.Proc {
						keep = false
						break
					}
				}
			}
			if keep {
				matchedProcs = append(matchedProcs, cpol.Proc)
			}
		}
	}
	return matchedProcs
}

// MatchConnect Matches a connect line in the policy.
// At this point a client has responded to an auth challenge. State is set up appropriately. If a rule matches
// it is applied to state (via the procs) which could set a flag or provides.
//
// Note that `state` is modified (and the actor inside it)
// Note that `actor` is also modified (gets a list of provides, gets zpr.role)
//
// Returns the actor attribute names that matched policy (or policies)
func (m *Matcher) MatchConnect(state *ConnectState) ([]string, error) {
	// We have a bunch of attribute sets.
	// See if the actors set is a supserset of any of them.
	m.log.Debug("[MX] MatchConnect", "state.actor", state.Actor.Hash())
	m.log.Debug("[MX] MatchConnect starts, claims offered:")
	for ck, cv := range state.Actor.GetAuthedClaims() {
		m.log.Debug("[MX] -- -- offered_claim", "key", ck, "value", cv)
	}

	// Given the attributes, see what policies match.
	matchedPolicyIndexes, err := m.matchAttrsToPolicies(state.Actor.GetAuthedClaims())
	if err != nil {
		return nil, err
	}
	if len(matchedPolicyIndexes) == 0 {
		return nil, errNoMatch
	}

	for _, pIdx := range matchedPolicyIndexes {
		id := "unknown"
		if pols := m.policy.GetPolicies(); int(pIdx) < len(pols) {
			id = pols[pIdx].GetId()
		}
		m.log.Debug(fmt.Sprintf("[MX] --> MatchConnect did match policy %d of %d", pIdx+1, len(matchedPolicyIndexes)), "id", id)
	}

	var procsRan []uint32 // Matching connect PROCS (already ran)
	attrChanges := 1

	// Loop here in case a policy connect procedure alters the actor claims. In that case
	// we will need to re-match the actor to the policy.
	//
	// TODO: Are we sure that the compiler or matcher will not allow matching of conflicting
	//       procedures? I guess it is all additive, but I'm not sure this is proved to be correct
	//       anywhere.

	// By default, we grant adapter role.
	state.Actor.SetAuthedClaim(actor.KAttrRole, &actor.ClaimV{V: "adapter", Exp: state.Actor.GetAuthExpires()})

	for attrChanges > 0 {
		matchedProcs := m.getProcsIfNotIn(matchedPolicyIndexes, procsRan)
		m.log.Debug("[MX] -- MatchConnect actor matched", "policyCount", len(matchedPolicyIndexes), "procCount", len(matchedProcs))

		for _, px := range matchedProcs {
			proc := m.policy.GetProcs()[px]
			if err := ExecCProc(proc, state); err != nil { // Run the proc, alters state
				m.log.WithError(err).Errorf("[MX] proc %X failed", px)
				return nil, errExecFail
			}
			procsRan = append(procsRan, px)
		}
		attrChanges = 0

		// The connect proc may set a node flag, which we use to set zpr.role.
		agnt := state.Actor
		if state.Node {
			m.log.Debug("[MX] -- MatchConnect -- -- NODE flag is set")
			if rc, ok := agnt.GetAuthedClaims()[actor.KAttrRole]; !ok || rc.V != "node" {
				agnt.SetAuthedClaim(actor.KAttrRole, &actor.ClaimV{V: "node", Exp: state.Actor.GetAuthExpires()})
				attrChanges++
			}
		}
		if state.VisaserviceDock {
			m.log.Debug("[MX] -- MatchConnect -- -- VISASERVICE_DOCK flag is set")
			if rc, ok := agnt.GetAuthedClaims()[actor.KAttrVisaServiceAdapter]; !ok || rc.V != "true" {
				agnt.SetAuthedClaim(actor.KAttrVisaServiceAdapter, &actor.ClaimV{V: "true", Exp: state.Actor.GetAuthExpires()})
				attrChanges++
			}
		}
		if attrChanges > 0 {
			// Re-run the matcher
			morePolicies, err := m.matchAttrsToPolicies(agnt.GetAuthedClaims())
			if err != nil {
				return nil, err
			}
			// Add the policies if they are new to us.
			prevMatchCount := len(matchedPolicyIndexes)
			for _, px := range morePolicies {
				isNew := true
				for _, i := range matchedPolicyIndexes {
					if i == px {
						isNew = false
						break
					}
				}
				if isNew {
					matchedPolicyIndexes = append(matchedPolicyIndexes, px)
				}
			}
			if prevMatchCount == len(matchedPolicyIndexes) {
				break // No change to policy set? We are done.
			}
		}
	}

	// If only decorator services matched, remove them.
	if len(state.Services) > 0 {
		nonDecoCount := 0
		for _, svc := range state.Services {
			if svc.Type == polio.SvcT_SVCT_DECORATOR {
				continue
			}
			nonDecoCount++
		}
		if nonDecoCount == 0 {
			// TODO: What if matching the provider of a decorator service is all that allows you to log in?
			//       Preprocessor/compiler should not add a connect rule in that case.
			state.Services = nil
			m.log.Info("[MX] only decorator services matched, removing them")
		}
	}

	// Get the list of unique actor keys that were used in matching a connect.
	uniqs := make(map[string]bool)
	for _, px := range matchedPolicyIndexes {
		for _, attrExpr := range m.policy.GetConnects()[px].GetAttrExprs() {
			uniqs[m.policy.GetAttrKeyIndex()[attrExpr.Key]] = true
		}
	}
	var matchedActorKeys []string
	for k := range uniqs {
		m.log.Debugf("[MX] -- connect matched on key %v", k)
		matchedActorKeys = append(matchedActorKeys, k)
	}

	var actorProvides []string
	for _, svc := range state.Services {
		m.log.Debugf("[MX] -- connect policy sets actor provides: %v", svc.Name)
		actorProvides = append(actorProvides, svc.Name)
	}
	// If visaservice flag is set, create a "virtual" service entry.
	if state.Visaservice {
		actorProvides = append(actorProvides, VisaServiceName)                         // TODO: compiler must prevent this from ever being defined.
		actorProvides = append(actorProvides, fmt.Sprintf("/zpr/%s", VisaServiceName)) // TODO: compiler must prevent this from ever being defined.
	}
	state.Actor.SetProvides(actorProvides)

	return matchedActorKeys, nil
}

// MatchTraffic tries to match a traffic signature to the policy in order to issue a visa.
// This is only used to create a visa.
//
// Multiple policies may match and in that case they are all returned.
//
// This does not pay any attention to TCP flags.
//
// Returns (LINE_REF, IS_FWD_MATCH, ERROR)
func (m *Matcher) MatchTraffic(td *snip.Traffic, srcActor, dstActor *ActorInfo) (cpols []*MatchedPolicy, err error) {
	polset := m.policiesForScope(td, srcActor, dstActor)
	m.log.Debugf("[MX] MatchTraffic found %d candidate policies based on scope", len(polset))
	if len(polset) == 0 {
		return nil, errNoMatchScope
	}

	// The policy attributes must match the _connecting_ actor.
	// If this is client->server then we are checking the client.
	// If this is server->client again, we are checking client.

POLICYLOOP:
	for _, pcy := range polset {

		clientAttrs := srcActor.ActorAttrs
		if !pcy.FWD {
			clientAttrs = dstActor.ActorAttrs
		}

		m.log.Debug("[MX] checking policy", "ID", pcy.CPol.GetId(), "FWD?", pcy.FWD)
		m.log.Debugf("[MX] -- actor claims attributes: %v", formatClaimedAttrs(clientAttrs))
		if len(clientAttrs) == 0 {
			m.log.Warn("[MX] client actor has no attributes") // probably indicates some sort of bug
		}

		// Build a map of claimed attribute keys to sets of values (broken out
		// from comma-separated lists) using integer codes.
		claimCodes := make(map[uint32]map[uint32]bool) // key code -> val code -> true
		for key, val := range clientAttrs {
			keyCode, exists := m.keyMap[key]
			if !exists {
				continue // attribute key not referenced by any policy
			}
			if _, exists := claimCodes[keyCode]; !exists {
				claimCodes[keyCode] = make(map[uint32]bool)
			}
			valFields := strings.Split(val.V, ",")
			for _, valField := range valFields {
				valFieldCode, exists := m.valMap[valField]
				if !exists {
					continue // attribute value (field) not referenced by any policy
				}
				claimCodes[keyCode][valFieldCode] = true
			}
		}

		// For this policy (pcy) to apply, all conditions must be met.
		for _, conds := range pcy.CPol.GetConditions() {
			if gotMatch, i, err := matchAttrExprs(conds.GetAttrExprs(), claimCodes, m.blankValIdx); err != nil {
				m.log.Debugf("[MX] -- failed to evaluate attribute expression %v: %v", formatAttrExpr(m.policy, conds.GetAttrExprs()[i]), err)
				continue POLICYLOOP
			} else if !gotMatch {
				m.log.Debugf("[MX] -- policy fails match on attribute expression %v", formatAttrExpr(m.policy, conds.GetAttrExprs()[i]))
				continue POLICYLOOP
			}
		}

		// If we successfully get through all conditions, then policy applies.
		// BUT, do not permit both FWD and REV matches.  TODO: Can we catch this at compile time?
		for _, mp := range cpols {
			if mp.FWD != pcy.FWD {
				return nil, fmt.Errorf("illegal match: forward and reverse")
			}
			if mp.CPol.ServiceId != pcy.CPol.ServiceId {
				return nil, fmt.Errorf("illegal match: multiple services")
			}
		}
		cpols = append(cpols, pcy)
	}

	if len(cpols) == 0 {
		return nil, errNoMatchConditions
	}

	return cpols, nil
}

func (m *Matcher) policiesForScope(td *snip.Traffic, srcActor, dstActor *ActorInfo) []*MatchedPolicy {
	var pset []*MatchedPolicy

	// HACK - The prototype compiler will allow for ICMPv4 and ICMPv6, but it always writes
	//        the scope protocol as ICMPv6 since the prototype ZPL does not differentiate.
	//        Therefore the matcher index always uses ICMP6.  If we are getting IPv4 traffic and
	//        the protocol is ICMP4 we pretend it is ICMP6.
	tdProtoNum := td.Proto.Num()
	if td.SrcAddr.Is4() && td.Proto == snip.ProtocolICMP4 {
		tdProtoNum = snip.ProtocolICMP6.Num()
	}

	// In all cases, either the source or destination must have a service to offer. Possibly they both do.
	m.log.Debug("[MX] matcher - running policiesForScope")
	for _, svcID := range dstActor.ActorProvides {
		m.log.Debug("[MX] found dest actor provides", "provides", svcID)
		if protIdx, match := m.trafficIdx[svcID]; match {
			m.log.Debug("[MX]  -- found service in match table", "protocolCount", len(protIdx))
			m.log.Debug("[MX]  -- ", "wanted_proto_num", tdProtoNum, "protIdx", protIdx)
			if portIdx, match := protIdx[tdProtoNum]; match {
				m.log.Debug("[MX]  -- found protocol in match table", "portCount", len(portIdx))
				if set, merr := m.matchy(td, true, portIdx, dstActor); len(set) > 0 { // FORWARD !
					m.log.Debugf("[MX]  -- -- matched %d policies on FWD", len(set))
					pset = append(pset, set...)
				} else if merr != nil {
					m.log.Debug("[MX] -- -- scope match failed", "reason", merr.Error(), "dir", "FWD")
				}
			}
		} else {
			m.log.Debugf("[MX]       FAILED to find service '%v' in our traffic index.  Dumping index::", svcID)
			for svcID, protIdx := range m.trafficIdx {
				m.log.Debug("[MX]         index level 1", "svcID", svcID, "->protocol+", protIdx)
			}

		}
	}
	for _, svcID := range srcActor.ActorProvides {
		m.log.Debug("[MX]  checking source actor provides", "provides", svcID)
		if protIdx, match := m.trafficIdx[svcID]; match {
			if portIdx, match := protIdx[tdProtoNum]; match {
				if set, merr := m.matchy(td, false, portIdx, dstActor); len(set) > 0 { // REVERSE !
					m.log.Debugf("[MX]  -- -- matched %d policies on REV", len(set))
					pset = append(pset, set...)
				} else if merr != nil {
					m.log.Debug("[MX] -- -- scope match failed", "reason", merr.Error(), "dir", "REV")
				}
			}
		}
	}
	m.log.Debug("[MX] matcher - policiesForScope completes", "matched_policy_count", len(pset))
	return pset
}

// matchy try to match the traffic to the policy based on scope.
// Return matched list could be empty, explanatory errors are sometimes returned.
func (m *Matcher) matchy(td *snip.Traffic, isFWD bool, portIdx map[uint32][]int, dstActor *ActorInfo) ([]*MatchedPolicy, error) {
	var pset []*MatchedPolicy
	var qPortVal uint32
	switch td.Proto {
	case snip.ProtocolTCP, snip.ProtocolUDP:
		if isFWD {
			qPortVal = uint32(td.DstPort)
		} else {
			qPortVal = uint32(td.SrcPort)
		}

	case snip.ProtocolICMP6, snip.ProtocolICMP4:
		// This is not quite right for ICMP. PING, for example, expects one typecode as a request
		// and the other as a response.  This index will match either typecode in either direction.  So more
		// detailed checking is required for ICMP.
		qPortVal = uint32(td.ICMPType) // using ICMP TYPE (not code)

	default: // not TCP, UDP or ICMP ??
		return nil, errUnknownProtocol
	}
	policies, match := portIdx[qPortVal]
	if !match {
		return nil, fmt.Errorf("port not in scope: %d", qPortVal)
	}
	var matchError error
	for _, px := range policies {
		cpol := m.policy.Policies[px]
		switch td.Proto {
		case snip.ProtocolICMP6, snip.ProtocolICMP4:
			// Eg policy says REQ-REP to 128, 129
			// so,
			//     128 must match client to service
			//     129 must match service to client
			//
			// We are client to service IF dst.Actor provides policy
			icmpFWD := dstActor.Provides(cpol.GetServiceId())
			if mpol := m.icmpSpecialHandling(cpol, qPortVal, icmpFWD); mpol != nil {
				pset = append(pset, mpol)
			}
		case snip.ProtocolTCP, snip.ProtocolUDP:
			if td.Proto == snip.ProtocolTCP {
				// if !isFWD && (td.Flags&0x10) == 0 { // Suspect ACK may not _always_ be set ??
				if !isFWD && ((td.Flags&0x02) > 0 && (td.Flags&0x10) == 0) { // SYN but not ACK
					matchError = errTCPRevSyn // Note that another policy may match so this error may not matter.
					continue
				}
			}
			pset = append(pset, &MatchedPolicy{
				CPol: cpol,
				FWD:  isFWD,
			})
		default:
			pset = append(pset, &MatchedPolicy{
				CPol: cpol,
				FWD:  isFWD,
			})
		}
	}
	if len(pset) > 0 {
		return pset, nil
	}
	return nil, matchError // matchError may be nil
}

func (m *Matcher) icmpSpecialHandling(cpol *polio.CPolicy, qPortVal uint32, isFWD bool) *MatchedPolicy {
	var meta *MatchMetadata
	// Special case for ICMP. If there are a pair of types (for request, response) then a forward query
	// must only match on a request, and a reverse must match on a response.
	keep := false
	for _, sc := range cpol.Scope {
		if (sc.Protocol == snip.ProtocolICMP6.Num()) || (sc.Protocol == snip.ProtocolICMP4.Num()) {
			icmpScope := sc.GetIcmp()
			if len(icmpScope.Codes) == 1 {
				if icmpScope.Codes[0] == qPortVal {
					meta = &MatchMetadata{
						IcmpType: icmpScope.GetType(),
					}
					keep = true
					break
				}
			} else if len(icmpScope.Codes) == 2 && icmpScope.Type == polio.ICMPT_ICMPT_REQREP {
				if isFWD {
					if icmpScope.Codes[0] == qPortVal {
						meta = &MatchMetadata{
							IcmpType: icmpScope.GetType(),
						}
						keep = true
						break
					}
				} else {
					if icmpScope.Codes[1] == qPortVal {
						meta = &MatchMetadata{
							IcmpType:               icmpScope.GetType(),
							IcmpRequiresAntecedent: true,
							IcmpAntecedent:         uint16(icmpScope.Codes[0]),
						}
						keep = true
						break
					}
				}
			} else {
				// must match one of the ports
				for _, pn := range icmpScope.Codes {
					if pn == qPortVal {
						meta = &MatchMetadata{
							IcmpType: icmpScope.GetType(),
						}
						keep = true
						break
					}
				}
				if keep {
					break
				}
			}
		}
	}
	if keep {
		return &MatchedPolicy{
			CPol:     cpol,
			FWD:      isFWD,
			Metadata: meta,
		}
	}
	return nil
}

func (m *Matcher) buildTrafficIndex() {
	for pIdx, cp := range m.policy.GetPolicies() {
		svcID := cp.GetServiceId()
		for _, sc := range cp.GetScope() {
			switch arg := sc.GetProtarg().(type) {
			case *polio.Scope_Pspec:
				m.trafficIndexInsertPortSpecs(svcID, sc.Protocol, arg.Pspec.GetSpec(), pIdx)
			case *polio.Scope_Icmp:
				icmp := arg.Icmp
				for _, tcode := range icmp.Codes {
					m.trafficIndexInsert(svcID, sc.Protocol, tcode, pIdx)
				}
			default:
				panic(fmt.Sprintf("unexpected Scope.protarg: %#v", sc.GetProtarg()))
			}
		}

	}
}

func (m *Matcher) trafficIndexInsertPortSpecs(svcID string, protocol uint32, pslist []*polio.PortSpec, pcyIdx int) {
	for _, psspec := range pslist {
		switch psarg := psspec.GetParg().(type) {
		case *polio.PortSpec_Port:
			m.trafficIndexInsert(svcID, protocol, psarg.Port, pcyIdx)
		case *polio.PortSpec_Pr:
			for i := psarg.Pr.Low; i <= psarg.Pr.High; i++ {
				m.trafficIndexInsert(svcID, protocol, i, pcyIdx)
			}
		default:
			panic(fmt.Sprintf("unexpected PortSpec.parg: %#v", psspec.GetParg()))
		}
	}
}

// trafficIndexInsert insert into our traffic matching lookup table.
// `svcID` is something like "/<system-name>/<service-name>""
func (m *Matcher) trafficIndexInsert(svcID string, protocol uint32, portOrTypeCode uint32, policyIdx int) {
	m.log.Debug("[MX] trafficIndexInsert", "service", svcID, "protocol", protocol, "portOrTypeCode", portOrTypeCode, "policy#", policyIdx)
	svcEnt := m.trafficIdx[svcID]
	if svcEnt == nil {
		m.trafficIdx[svcID] = make(map[uint32]map[uint32][]int)
		svcEnt = m.trafficIdx[svcID]
	}
	protEnt := svcEnt[protocol]
	if protEnt == nil {
		svcEnt[protocol] = make(map[uint32][]int)
		protEnt = svcEnt[protocol]
	}
	policies := protEnt[portOrTypeCode]
	if policies == nil {
		protEnt[portOrTypeCode] = []int{policyIdx}
		return
	}
	// no dupes
	for _, x := range policies {
		if x == policyIdx {
			return
		}
	}
	protEnt[portOrTypeCode] = append(protEnt[portOrTypeCode], policyIdx)
}

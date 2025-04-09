package vservice

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/snio/zds"
)

// TODO: Most of these funcs were using the shim objects (CoonnectionRequest, ConnectionResult)
//       that are now confied to zprn/vsshims.  Need to rework these functions.
//

// TODO: A version of approve connection to use when there is no policy.
//       Using data in the node configuration file:
//          - the certifiate of the visa service adapter.
//          - an attribute to match on (ER, no don't bother -- just match on the cert)
//
// Check if the hmac in the payload uses the private key associated with our known certificate.
// IF SO,
//    - get ready for a message from the visa service (visa-service-hello)
//
// Once we get a policy, we must ensure that the PROC for our node sets the visaservice flag.
// If not, we should shutdown.
//
// Basic VS visa should already be installed (at startup).
//
// NOTE we are in vsimpl here and probably want to be in node somewhere.
//

// ApproveConnection check connection against validation and policy.  If `authedActor` is set we assume that this is being called by
// the node to "self approve" its own tunnel, so we skip validation.
//
// The EPID on the connection request is either a new one created by the node, or
// one that the client has submitted at HELLO.
func (vs *VSInst) ApproveConnection(cr *vsapi.ConnectRequest) (*actor.Actor, error) {
	// The policy in use for this approval. Maybe pass in? But the VS should have it, right?
	// Note that the auth-service has a policy which is going to be the one used.
	curpol, curmatcher, configID := vs.getPolicyMatcherConfig()

	var err error
	var validatedActor *actor.Actor

	// First validate credentials with authorities, which will yied an authenticated Actor.
	validatedActor, err = vs.validateCredentials(curpol, cr)
	if err != nil {
		return nil, fmt.Errorf("validate credentials failed: %w", err)
	}
	for k, v := range validatedActor.GetAuthedClaims() {
		vs.log.Debugf("post-validate actor credential: %v -> %v", k, v)
	}

	// Set connect-via
	dockAddr, ok := netip.AddrFromSlice(cr.DockAddr)
	if ok {
		validatedActor.SetAuthedClaimWithExp(actor.KAttrConnectVia, dockAddr.String(), validatedActor.GetAuthExpires())
	} else {
		vs.log.Warn("unable to parse dock address for connect-via claim", "addr", cr.DockAddr)
	}
	// Then run through any connect policy lines.
	_, _, err = vs.applyConnectPolicy(curpol, curmatcher, dockAddr, validatedActor)
	if err != nil {
		vs.log.WithError(err).Info("apply policy failed")
		return nil, fmt.Errorf("apply policy failed: %w", err)
	}

	// At this point the actor must have an address.
	zprAddr, ok := validatedActor.GetZPRID()
	if !ok {
		vs.log.Error("failed to assign an address to the actor, denying connection")
		return nil, fmt.Errorf("failed to get an address")
	}

	// Actor has N attributes, some M of those attributes (where M<=N) have been
	// matched to connect policy.  I'd like a table tracking which attributes are
	// in use by which actors.
	if validatedActor.GetConfigID() != configID {
		vs.log.Error("auth'd actor configID should match current policy configID", "got", validatedActor.GetConfigID(), "expected", configID)
	}

	// presumably nodes get added when they HELLO. But they may also need updating here.
	if validatedActor.IsAdapter() {
		vs.actorDB.AddAdapter(zprAddr, zprAddr, validatedActor)
	}

	return validatedActor, nil
}

// applyConnectPolicy runs the old connect "procedures" from policy, creating the flowstate.
// The passed actor may be modified by adding to the list of provided services.
//
// Returns the list of keys that matched along with other details.
// The passed actor is almost certainly modified (in place).
// The actor returned is the same pointer as the one passed in.
func (vs *VSInst) applyConnectPolicy(curpol *policy.Policy, matcher *policy.Matcher, dockZPRAddr netip.Addr, agnt *actor.Actor) (*actor.Actor, []string, error) {
	// Note passing of "configurator" here -- do we need that?
	fs, err := policy.NewConnectState(agnt, vs, dockZPRAddr, vs.log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create a FlowState: %w", err)
	}
	matchedAttrKeys, err := matcher.MatchConnect(fs) // sets claim zpr.role (among other things).
	if err != nil {
		return nil, nil, err
	}
	return fs.Actor, matchedAttrKeys, nil
}

// validateCredentials uses the data source API to validate the actor credentials.
// The ConnectionRequest `cr` is possibly modified (claims).
func (vs *VSInst) validateCredentials(curpol *policy.Policy, cr *vsapi.ConnectRequest) (*actor.Actor, error) {

	// externalSvc, externalDomain, externalPrefix := curpol.GetExternalAuthority()
	// vs.log.Debug("(MakeAuthDec) EXTERNAL authority is set", "prefix", externalPrefix)

	// In case sn.authority is not set explicitly, we set it from incomming
	// auth types.

	var err error
	var authPrefix string

	if vs.validationEnabled {
		// If there are no challenge-responses, we cannot validate anything.
		if len(cr.ChallengeResponses) == 0 {
			return nil, fmt.Errorf("no challenge responses")
		}
		authPrefix, err = vs.SelectValidateDSPrefix(curpol, cr)
		if err != nil {
			return nil, err
		}
	}

	// The address assigned to the actor is either requested by the actor and propogated by the node
	// into the actors claims, or it is assigned by the node, or it is not set at all (and must be set by policy).
	var reqAddr netip.Addr
	if epidClaim, found := cr.Claims[actor.KAttrEPID]; found {
		reqAddr, err = netip.ParseAddr(epidClaim)
		if err != nil {
			vs.log.WithError(err).Warn("EPID claim is invalid", "claim", epidClaim)
		}
		delete(cr.Claims, actor.KAttrEPID)
	}

	// If there is an "authority" claim, stip it out now.
	delete(cr.Claims, actor.KAttrActorAuthority)

	agnt := actor.NewActorFromUnsubstantiatedClaims(cr.Claims) // TODO: Why bother with the unsubstantiated claims?
	vs.log.Debug("NEW ACTOR", "claims_in", cr.Claims)

	var aok *auth.AuthenticateOK

	if vs.validationEnabled {
		var chal zds.Challenge
		if err := proto.Unmarshal(cr.Challenge, &chal); err != nil {
			return nil, fmt.Errorf("failed to unmarshal challenge: %w", err)
		}
		var chalResps []*zds.ChallengeResponse
		for i, crb := range cr.ChallengeResponses {
			var zcr zds.ChallengeResponse
			if err := proto.Unmarshal(crb, &zcr); err != nil {
				return nil, fmt.Errorf("failed to unmarshal challenge response %d: %w", i+1, err)
			}
			chalResps = append(chalResps, &zcr)
		}

		// Finally, perform authentication.  Note `reqAddr` may be unset.
		// Blocking call:
		aok, err = vs.authr.Authenticate(authPrefix, reqAddr, &chal, chalResps, cr.Claims) // hmm, no prefix?
		if err != nil {
			return nil, fmt.Errorf("authenticate failed: %w", err)
		}
	} else {
		aok, err = vs.authr.SelfAuthenticate(reqAddr, cr.Claims)
		if err != nil {
			return nil, fmt.Errorf("self-authenticate failed: %w", err)
		}
	}

	aok.Claims[actor.KAttrAuthority] = &actor.ClaimV{V: strings.Join(aok.Prefixes, ","), Exp: aok.Expire}

	// If an authority sets <AUTHID>.zpr.addr, convert that to just "zpr.addr"
	for _, authID := range aok.Prefixes {
		if epidVal, found := aok.Claims[fmt.Sprintf("%v.%v", authID, actor.KAttrEPID)]; found {
			if existing, ok := aok.Claims[actor.KAttrEPID]; ok {
				// sn.epid is already set.
				if existing != epidVal {
					// And it is different??
					vs.log.Warn("mutliple EPID claims from authorities, first one wins", "winner", existing, "ignoring", epidVal)
				}
			} else {
				// Not set.
				aok.Claims[actor.KAttrEPID] = epidVal
			}
		}
	}

	if _, ok := agnt.GetZPRID(); !ok {
		vs.log.Debug("no ZPRID claim found on authenticated actor")
		// Should be set later then in policy -- or if not it is a connection error.
	}

	_, _, cid := vs.getPolicyMatcherConfig()
	agnt.SetAuthenticated(aok.Claims, aok.Expire, aok.Prefixes, aok.Identities, cid)
	// TODO: We get these "credentials" from the auth service too (aok.Credentials)
	//       I'm no longer sure what these are or how to use them.

	// Validation succeeds!
	// Need to use the claims from the validation claims from user to match an
	// actor claim in policy. MatchConnect will only work with a valid claim.

	vs.log.Debug("validation success, dumping claims")
	for k, v := range cr.Claims {
		vs.log.Debugf("*** [submitted-claim]  '%v' => '%v'", k, v)
	}
	for k, v := range aok.Claims {
		vs.log.Debugf("*** [accepted-claim ]  '%v' => '%v'", k, v.V)
	}

	// At this point the authentication has succeeded, but we have not yet checked
	// connection policy.
	return agnt, nil
}

// SelectValidateDSPrefix figure out the data source (or sources) which will
// be required to validate this connection request.
//
// If multiple are required, the are returned as comma separated string.
//
// Used by validateCredential function. Private function -- capitalized so that I
// can unit test it.
func (vs *VSInst) SelectValidateDSPrefix(curpol *policy.Policy, cr *vsapi.ConnectRequest) (string, error) {
	var connectAuthority string

	if apfx, found := cr.Claims[actor.KAttrActorAuthority]; found {
		connectAuthority = apfx
	} else if apfx, found := cr.Claims[actor.KAttrAuthority]; found {
		// This is the older way of doing things.
		connectAuthority = apfx
	}

	var chalResps []*zds.ChallengeResponse
	for i, crb := range cr.ChallengeResponses {
		var zcr zds.ChallengeResponse
		if err := proto.Unmarshal(crb, &zcr); err != nil {
			return "", fmt.Errorf("failed to unmarshal challenge response %d: %w", i+1, err)
		}
		chalResps = append(chalResps, &zcr)
	}

	// Before calling for authentication check if we know about the domain.
	// If not, then check to see if it is on a remote node and add it in.
	// (TODO: Not sure why this wouldn't happen automatically...)
	usingExternal := false
	var xAuthSvc *polio.Service
	var authPrefix string
	for _, crb := range chalResps {
		if aa, err := actor.ParseAuthAttr(crb.GetRespSpec()); err == nil {
			if aa.IsExternal() {
				usingExternal = true
				break
			}
		}
	}
	if usingExternal {
		if connectAuthority == "" { // No auth requested, use our default if we have one.
			if svcs := curpol.ExportBundle().Services; len(svcs) == 1 {
				xAuthSvc = svcs[0] // great, there is only one so use it.
				connectAuthority = xAuthSvc.Prefix
			} else {
				return "", fmt.Errorf("no authority claim, unable to validate connection")
			}
		}
		xAuthSvc = curpol.AuthServiceForPrefix(connectAuthority)
		if xAuthSvc == nil {
			return "", fmt.Errorf("unknown auth service: %v", connectAuthority)
		}
		authPrefix = xAuthSvc.GetPrefix()
	} else {
		if connectAuthority == "" {
			vs.log.Debug("(MakeAuthDec) zpr.authority is NOT set, attempting to guess")
			if apfx, err := vs.guessSnAuthority(curpol, chalResps); err != nil {
				return "", fmt.Errorf("failed to guess authority: %w", err)
			} else {
				connectAuthority = apfx
			}
		}
		authPrefix = connectAuthority
	}

	return authPrefix, nil
}

// guessSnAuthority tries to figure out the data source PREFIX for the data source
// which should be the validation authority for this challenge response.
//
// Never called if there is an external auth present in the challenge response.
//
// The result is a prefix value.
func (vs *VSInst) guessSnAuthority(curpol *policy.Policy, arbs []*zds.ChallengeResponse) (string, error) {

	// If there is just one external authority, we can use that as a default.
	var extAuth *polio.Service
	for _, svc := range curpol.ExportBundle().GetServices() {
		if svc.GetType() == polio.SvcT_SVCT_AUTH {
			if extAuth == nil {
				extAuth = svc
			} else {
				// Too many.
				extAuth = nil
				break
			}
		}
	}
	var externalPrefix string
	if extAuth != nil {
		externalPrefix = extAuth.GetPrefix()
	}

	// Either actors need to tell us what they expect their authorities to
	// be or we need a way to set a default in policy.  For now, if there is just
	// one non-external authority we take that to be default.
	defaultInternalAuthority := curpol.GetDefaultINTAuthority()
	if defaultInternalAuthority == "" {
		vs.log.Warn("unable to determine default internal authority")
	}

	uniqauths := make(map[string]bool)
	for _, crb := range arbs {
		vs.log.Debug("(guessSnAuthority) parsing spec", "spec", crb.GetRespSpec())
		if aa, err := actor.ParseAuthAttr(crb.GetRespSpec()); err != nil {
			return "", fmt.Errorf("bad challenge response spec: %w", err)
		} else {
			if aa.IsExternal() && (externalPrefix != "") {
				// use default authority from policy
				vs.log.Debug("(guessSnAuthority) adding default ext authority")
				uniqauths[externalPrefix] = true
			} else if ity := aa.GetAuthority(); ity != "" {
				vs.log.Debug("(guessSnAuthority) adding authority", "authority", ity)
				uniqauths[ity] = true
			} else if defaultInternalAuthority != "" {
				vs.log.Debug("(guessSnAuthority) adding default INT authority")
				uniqauths[defaultInternalAuthority] = true
			} else {
				// This is a fail. We need to know who the authority is in order to
				// have a hope of matching the actor line in the policy.
				return "", fmt.Errorf("default internal authority not set and incoming spec lacks authority name")
			}
		}
	}
	if len(uniqauths) == 0 {
		return "", fmt.Errorf("unable to determine zpr.authority setting")
	}
	var auths []string
	for k := range uniqauths {
		auths = append(auths, k)
	}
	sort.Strings(auths)
	return strings.Join(auths, ","), nil
}

// Note that this is not a reversible operation.  Converting to vsapi.Actor
// drops a lot of actor info.  The visa service has all the real actor info
// so can look the details up when it needs them.
func actorToVsapiActor(a *actor.Actor, tetherAddr []byte) *vsapi.Actor {
	aa := &vsapi.Actor{
		ActorType:   vsapi.ActorType_ADAPTER, // default
		Attrs:       make(map[string]string),
		AuthExpires: a.GetAuthExpires().Unix(),
		TetherAddr:  tetherAddr,
		Ident:       a.GetIdentity(),
	}
	for k, v := range a.GetAuthedClaims() {
		aa.Attrs[k] = v.V // note we drop the claim expiration here. Ok?
		if k == actor.KAttrRole && v.V == "node" {
			aa.ActorType = vsapi.ActorType_NODE
		}
	}
	if _, found := aa.Attrs[actor.KAttrHash]; !found {
		if a.Hash() != "" {
			aa.Attrs[actor.KAttrHash] = a.Hash()
		}
	}
	if _, found := aa.Attrs[actor.KAttrConfigID]; !found {
		aa.Attrs[actor.KAttrConfigID] = fmt.Sprintf("%d", a.GetConfigID())
	}
	if zid, ok := a.GetZPRID(); ok {
		aa.ZprAddr = zid.AsSlice()
	}
	aa.Provides = append(aa.Provides, a.GetProvides()...)
	return aa
}

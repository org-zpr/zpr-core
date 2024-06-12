package vservice

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vs/pkg/policy"

	"zpr.org/vsx/snio/vsio"
	"zpr.org/vsx/snio/zds"
	"zpr.org/vsx/polio"
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

// ApproveConnection check connection against validation and policy.  If `authedAgent` is set we assume that this is being called by
// the node to "self approve" its own tunnel, so we skip validation.
//
// The EPID on the connection request is either a new one created by the node, or
// one that the client has submitted at HELLO.
//
// Passing an `authedAgent` is a hack to deal with implementation decision to have a tunnel address on
// each node. This tunnel address acts like a connection (with id of -1). So traffic can flow over
// it. Here we "authenticate" it (in a manner of speaking).
func (vs *VSInst) ApproveConnection(cr *vsio.VSConnectRequest, authedAgent *agent.Agent) (*vsio.VSConnectResponse, error) {
	// The policy in use for this approval. Maybe pass in? But the VS should have it, right?
	// Note that the auth-service has a policy which is going to be the one used.
	curpol, curmatcher, configID := vs.getPolicyMatcherConfig()

	var err error
	var validatedAgent *agent.Agent
	resp := &vsio.VSConnectResponse{
		ConId: cr.GetConId(),
	}

	if authedAgent == nil {
		// First validate credentials with authorities, which will yied an authenticated Agent.
		validatedAgent, err = vs.validateCredentials(curpol, cr)
		if err != nil {
			return nil, fmt.Errorf("validate credentials failed: %w", err)
		}
		for k, v := range validatedAgent.GetAuthedClaims() {
			vs.log.Debugf("post-validate agent credential: %v -> %v", k, v)
		}
	} else {
		validatedAgent = authedAgent
		validatedAgent.SetConfigID(configID)
		// TODO: Update expires?

	}
	// Set connect-via
	dockAddr, ok := cr.ParseDockAddr()
	if ok {
		validatedAgent.SetAuthedClaimWithExp(agent.KAttrConnectVia, dockAddr.String(), validatedAgent.GetAuthExpires())
	} else {
		vs.log.Warn("unable to parse dock address for connect-via claim", "addr", cr.DockAddr)
	}
	// Then run through any connect policy lines.
	_, _, err = vs.applyConnectPolicy(curpol, curmatcher, dockAddr, validatedAgent)
	if err != nil {
		vs.log.WithError(err).Info("apply policy failed")
		return nil, fmt.Errorf("apply policy failed: %w", err)
	}

	// Agent has N attributes, some M of those attributes (where M<=N) have been
	// matched to connect policy.  I'd like a table tracking which attributes are
	// in use by which agents.
	if validatedAgent.GetConfigID() != configID {
		vs.log.Error("auth'd agent configID should match current policy configID", "got", validatedAgent.GetConfigID(), "expected", configID)
	}

	if signature, err := computeSignatureOverAgent(validatedAgent, vs.agentSigningKey); err == nil {
		validatedAgent.Sign(SigningKeyID, signature)
	} else {
		vs.log.WithError(err).Warn("failed to sign agent")
	}

	// Convert the agent.Agent into an snio.Agent for sending back
	resp.Agent = agentToSnioAgent(validatedAgent, nil) // we don't know the tether address.
	resp.Success = true
	return resp, nil
}

// applyConnectPolicy runs the old connect "procedures" from policy, creating the flowstate.
// The passed agent may be modified by adding to the list of provided services.
//
// Returns the list of keys that matched along with other details.
// The passed agent is almost certainly modified (in place).
// The agent returned is the same pointer as the one passed in.
func (vs *VSInst) applyConnectPolicy(curpol *policy.Policy, matcher *policy.Matcher, dockZPRAddr netip.Addr, agnt *agent.Agent) (*agent.Agent, []string, error) {
	// Note passing of "configurator" here -- do we need that?
	fs, err := policy.NewConnectState(agnt, vs, dockZPRAddr, vs.log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create a FlowState: %w", err)
	}
	matchedAttrKeys, err := matcher.MatchConnect(fs) // sets claim zpr.role (amoung other things).
	if err != nil {
		return nil, nil, err
	}
	return fs.Agent, matchedAttrKeys, nil
}

// validateCredentials uses the data source API to validate the agent credentials.
// The ConnectionRequest `cr` is possibly modified (claims).
func (vs *VSInst) validateCredentials(curpol *policy.Policy, cr *vsio.VSConnectRequest) (*agent.Agent, error) {

	// externalSvc, externalDomain, externalPrefix := curpol.GetExternalAuthority()
	// vs.log.Debug("(MakeAuthDec) EXTERNAL authority is set", "prefix", externalPrefix)

	// In case sn.authority is not set explicitly, we set it from incomming
	// auth types.

	authPrefix, err := vs.SelectValidateDSPrefix(curpol, cr)
	if err != nil {
		return nil, err
	}

	// Sanity check: at this point there is no changing EPID, warn if it look suspicious
	reqAddr, ok := cr.ParseReqAddr()
	if ok {
		if epidClaim, found := cr.Claims[agent.KAttrEPID]; found {
			if reqAddr.String() != epidClaim {
				vs.log.Warn("EPID assigned does not match claim", "assigned", reqAddr.String(), "claimed", epidClaim)
			}
		}
	}

	// If there is an "authority" claim, stip it out now.
	delete(cr.Claims, agent.KAttrAgentAuthority)

	agnt := agent.NewAgentFromUnsubstantiatedClaims(cr.Claims) // TODO: Why bother with the unsubstantiated claims?
	vs.log.Debug("NEW AGENT", "claims_in", cr.Claims)

	// Finally, perform authentication.
	// Blocking call:
	aok, err := vs.authr.Authenticate(authPrefix, reqAddr, cr.Chal, cr.ChalResp, cr.Claims) // hmm, no prefix?
	if err != nil {
		return nil, fmt.Errorf("authenticate failed: %w", err)
	}

	aok.Claims[agent.KAttrAuthority] = &agent.ClaimV{V: strings.Join(aok.Prefixes, ","), Exp: aok.Expire}

	// If an authority sets <AUTHID>.zpr.addr, convert that to just "zpr.addr"
	for _, authID := range aok.Prefixes {
		if epidVal, found := aok.Claims[fmt.Sprintf("%v.%v", authID, agent.KAttrEPID)]; found {
			if existing, ok := aok.Claims[agent.KAttrEPID]; ok {
				// sn.epid is already set.
				if existing != epidVal {
					// And it is different??
					vs.log.Warn("mutliple EPID claims from authorities, first one wins", "winner", existing, "ignoring", epidVal)
				}
			} else {
				// Not set.
				aok.Claims[agent.KAttrEPID] = epidVal
			}
		}
	}

	// Sanity check: again, at this point there is no changing EPID.
	reqAddr, ok = cr.ParseReqAddr()
	if ok {
		if epidClaim, found := aok.Claims[agent.KAttrEPID]; found {
			if reqAddr.String() != epidClaim.V {
				vs.log.Error("EPID assigned does not match epid post auth", "assigned", reqAddr.String(), "post_auth", epidClaim)
				return nil, fmt.Errorf("auth attempt to re-assign EPID")
			}
		}
	}
	// Finally, if EPID has not been set by auth claim, make sure the agent has it.
	if _, ok := agnt.GetZPRID(); !ok {
		agnt.SetAuthedClaimWithExp(agent.KAttrEPID, reqAddr.String(), aok.Expire)
	}

	_, _, cid := vs.getPolicyMatcherConfig()
	agnt.SetAuthenticated(aok.Claims, aok.Expire, aok.Prefixes, aok.Identities, cid)
	// TODO: We get these "credentials" from the auth service too (aok.Credentials)
	//       I'm no longer sure what these are or how to use them.

	// Validation succeeds!
	// Need to use the claims from the validation claims from user to match an
	// agent claim in policy. MatchConnect will only work with a valid claim.

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
func (vs *VSInst) SelectValidateDSPrefix(curpol *policy.Policy, cr *vsio.VSConnectRequest) (string, error) {
	var connectAuthority string

	if apfx, found := cr.Claims[agent.KAttrAgentAuthority]; found {
		connectAuthority = apfx
	} else if apfx, found := cr.Claims[agent.KAttrAuthority]; found {
		// This is the older way of doing things.
		connectAuthority = apfx
	}

	// Before calling for authentication check if we know about the domain.
	// If not, then check to see if it is on a remote node and add it in.
	// (TODO: Not sure why this wouldn't happen automatically...)
	usingExternal := false
	var xAuthSvc *polio.Service
	var authPrefix string
	for _, crb := range cr.ChalResp {
		if aa, err := agent.ParseAuthAttr(crb.GetRespSpec()); err == nil {
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
			if apfx, err := vs.guessSnAuthority(curpol, cr.ChalResp); err != nil {
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

	// Either agents need to tell us what they expect their authorities to
	// be or we need a way to set a default in policy.  For now, if there is just
	// one non-external authority we take that to be default.
	defaultInternalAuthority := curpol.GetDefaultINTAuthority()
	if defaultInternalAuthority == "" {
		vs.log.Warn("unable to determine default internal authority")
	}

	uniqauths := make(map[string]bool)
	for _, crb := range arbs {
		vs.log.Debug("(guessSnAuthority) parsing spec", "spec", crb.GetRespSpec())
		if aa, err := agent.ParseAuthAttr(crb.GetRespSpec()); err != nil {
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
				// have a hope of matching the agent line in the policy.
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

// copied from prototype snet/transcode/agent.go
func agentToSnioAgent(a *agent.Agent, tetherAddr []byte) *vsio.Agent {
	aa := &vsio.Agent{
		Authenticated: a.IsAuthenticated(),
		AuthClaims:    make(map[string]*vsio.AClaim),
		AuthIds:       a.GetAuthIDs(),
		AuthTokens:    a.GetAuthTokens(),
		AuthExpires:   a.GetAuthExpires().Format(time.RFC3339),
		UnsubClaims:   a.GetClaims(),
		Hashval:       a.Hash(),
		Ident:         a.GetIdentity(),
		Provides:      a.GetProvides(),
		ConfigId:      a.GetConfigID(),
		TetherAddr:    tetherAddr,
	}
	for k, v := range a.GetAuthedClaims() {
		aa.AuthClaims[k] = &vsio.AClaim{
			Cval: v.V,
			Exp:  v.Exp.Unix(),
		}
	}
	if zid, ok := a.GetZPRID(); ok {
		aa.AuthAddr = zid.AsSlice()
	}
	return aa
}

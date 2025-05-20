package vservice

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsapi"
)

// ApproveConnection check connection against validation and policy.
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
	_, _, err = vs.applyConnectPolicy(curmatcher, dockAddr, validatedActor)
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

	// Log the provided services -- trying to figure out what to do with the adapter facing auth services.
	for _, prov := range validatedActor.GetProvides() {
		var stype string
		if svc := curpol.ServiceByName(prov); svc != nil {
			stype = svc.Type.String()
		} else {
			stype = "unknown"
		}
		vs.log.Info("new actor provides", "service", prov, "type", stype)
	}

	return validatedActor, nil
}

// applyConnectPolicy runs the old connect "procedures" from policy, creating the flowstate.
// The passed actor may be modified by adding to the list of provided services.
//
// Returns the list of keys that matched along with other details.
// The passed actor is almost certainly modified (in place).
// The actor returned is the same pointer as the one passed in.
func (vs *VSInst) applyConnectPolicy(matcher *policy.Matcher, dockZPRAddr netip.Addr, agnt *actor.Actor) (*actor.Actor, []string, error) {
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
func (vs *VSInst) validateCredentials(curpol *policy.Policy, cr *vsapi.ConnectRequest) (*actor.Actor, error) {
	var err error
	var authPrefix string

	// If there are no challenge-responses, we cannot validate anything.
	if len(cr.ChallengeResponses) == 0 {
		return nil, fmt.Errorf("no challenge responses")
	}

	authBlobs, err := vs.ParseAuthenticatioBlobs(cr)
	if err != nil {
		vs.log.WithError(err).Warn("failed to parse authentication blobs")
		return nil, fmt.Errorf("failed to parse authentication blobs")
	}

	// Current ref-impl supports bootstrap only and just a single blob.
	// Note that in some ZPRnet configurations, bootstrap may not be available (ie, once we have real auth services).
	// Also in order to process bootstrap we need CN:KEY mappings in the policy.
	if len(authBlobs) != 1 {
		return nil, fmt.Errorf("exactly one authentication blob must be provided")
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

	var authSuccesses []*auth.AuthenticateOK

	for i, blb := range authBlobs {
		authPrefix, err = vs.SelectValidateDSPrefix(curpol, blb)
		if err != nil {
			vs.log.WithError(err).Warn("failed to select a validation prefix for blob", "blob_idx", i)
			return nil, err
		}

		// Perform authentication.  Note `reqAddr` may be unset.
		// Blocking call:
		aok, err := vs.authr.Authenticate(authPrefix, reqAddr, blb, cr.Claims)
		if err != nil {
			vs.log.WithError(err).Warn("validate credentials: blob authentication failed", "prefix", authPrefix)
			return nil, fmt.Errorf("authenticate failed for blob %d (%s): %w", i+1, authPrefix, err)
		}
		vs.log.Info("authentication success", "authPrefix", authPrefix)
		authSuccesses = append(authSuccesses, aok)
	}

	// TODO: Need to combine the results of ALL the authentications.
	if len(authSuccesses) > 1 {
		return nil, fmt.Errorf("multiple authentication results not yet supported") // TODO
	}
	combinedAuth := authSuccesses[0]

	combinedAuth.Claims[actor.KAttrAuthority] = &actor.ClaimV{V: strings.Join(combinedAuth.Prefixes, ","), Exp: combinedAuth.Expire}

	// TODO: How/when do we assign an address to the actor?

	if _, ok := agnt.GetZPRID(); !ok {
		vs.log.Debug("no ZPRID claim found on authenticated actor")
		// Should be set later then in policy -- or if not it is a connection error.
	}

	_, _, cid := vs.getPolicyMatcherConfig()
	agnt.SetAuthenticated(combinedAuth.Claims, combinedAuth.Expire, combinedAuth.Prefixes, combinedAuth.Identities, cid)
	// TODO: We get these "credentials" from the auth service too (aok.Credentials)
	//       I'm no longer sure what these are or how to use them.

	// Validation succeeds!
	// Need to use the claims from the validation claims from user to match an
	// actor claim in policy. MatchConnect will only work with a valid claim.

	vs.log.Debug("validation success, dumping claims")
	for k, v := range cr.Claims {
		vs.log.Debugf("*** [submitted-claim]  '%v' => '%v'", k, v)
	}
	for k, v := range combinedAuth.Claims {
		vs.log.Debugf("*** [accepted-claim ]  '%v' => '%v'", k, v.V)
	}

	// At this point the authentication has succeeded, but we have not yet checked
	// connection policy.
	return agnt, nil
}

// Parse the authentication blobgs from the ChallengeResponses in the ConnectRequest.
// All the blobs must parse for this to return successfully.
func (vs *VSInst) ParseAuthenticatioBlobs(cr *vsapi.ConnectRequest) ([]auth.Blob, error) {
	var blobs []auth.Blob
	for i, respBuf := range cr.ChallengeResponses {
		// respBuf is a string of base64 encoded JSON.
		blob, err := auth.DecodeBlob(string(respBuf))
		if err != nil {
			return nil, fmt.Errorf("failed to decode blob %d or %d: %w", i+1, len(cr.ChallengeResponses), err)
		}
		blobs = append(blobs, blob)
	}
	return blobs, nil
}

// SelectValidateDSPrefix figure out the data source (or sources) which will
// be required to validate this connection request.
//
// If multiple are required, the are returned as comma separated string.
//
// Used by validateCredential function. Private function -- capitalized so that I
// can unit test it.
func (vs *VSInst) SelectValidateDSPrefix(curpol *policy.Policy, blob auth.Blob) (string, error) {
	if blob.GetBlobType() == auth.BlobT_SS {
		return auth.AUTH_PREFIX_BOOTSTRAP, nil
	}

	// The ASA is a ZPR IPv6 address of an authentication service.

	acBlob := blob.(*auth.ZdpAuthCodeBlob)

	asaSockAddr, err := netip.ParseAddrPort(acBlob.Asa)
	if err != nil {
		return "", fmt.Errorf("invalid ASA socket address: '%v': %w", acBlob.Asa, err)
	}

	// The ASA addr will match a ZPR address assigned to the actor facing interface of an auth service.
	// We will need to somehow associate that with the vs facing service.
	// For now I assume that the same actor that registers one also registers the other.
	// TODO: Needs more thought.

	asaActor, err := vs.actorDB.ActorAtContactAddr(asaSockAddr.Addr())
	if err != nil {
		return "", fmt.Errorf("unable to locate actor for ASA address '%v': %w", asaSockAddr.Addr(), err)
	}

	// Now look up the auth service.
	actorServices := asaActor.GetProvides()
	var matched string
	for _, sname := range curpol.GetVisaServiceValidationServiceNames() {
		if slices.Contains(actorServices, sname) {
			matched = sname
		}
	}
	if matched == "" {
		return "", fmt.Errorf("no matching VS auth service found for ASA address '%v'", asaSockAddr.Addr())
	}
	if svc := curpol.ServiceByName(matched); svc == nil {
		return "", fmt.Errorf("no VS auth service found with name '%v'", matched)
	} else {
		return svc.GetPrefix(), nil
	}
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

package vservice

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"

	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/adb"
	"zpr.org/vs/pkg/vservice/auth"
)

type VisaService struct {
	log                   logr.Logger
	cn                    string
	myAddr                netip.Addr // visa serice ZPR contact address
	authToken             []byte
	vsWg                  sync.WaitGroup
	shutdownC             chan struct{} // when closed our run() fuction will return
	initialPolicyFile     string
	authService           auth.AuthService
	maxAuthDuration       time.Duration
	bootstrapAuthDuration time.Duration

	keys struct {
		policyCheckingKey    *rsa.PublicKey    // for checking policy signature
		adminServiceTLSCreds *tls.Config       // for admin HTTP service
		visaServiceTLSCreds  *tls.Config       // thrift service TLS
		tokenSigningKey      *rsa.PrivateKey   // for signing JWT tokens
		authorityCert        *x509.Certificate // for checking certififactes from nodes/adapters
	}

	service struct {
		inst      *VSInst
		shutdownC chan struct{} // closes when the instance stops
	}

	policy struct { // current policy and configuration
		sync.RWMutex
		config uint64
		policy *policy.Policy
	}
}

// `bootstrapAuthDuration` is used to set the expiration of the self-authentication
// for the visa serviec actor as well as the initial visas handed to the first
// connecting node.  This would normally be short (~1hr).
func NewVisaService(initialPolicyFile string,
	vs_cn string,
	privateKey *rsa.PrivateKey,
	vsServerCreds *tls.Config,
	bootstrapAuthDuration, maxAuthDuration time.Duration,
	authorityCert *x509.Certificate,
	log logr.Logger) (*VisaService, error) {

	if _, err := os.Stat(initialPolicyFile); err != nil {
		return nil, fmt.Errorf("policy file stat error: %w", err)
	}
	if bootstrapAuthDuration > maxAuthDuration {
		return nil, errors.New("bootstrap auth duration exceeds max auth duration")
	}
	svc := &VisaService{
		log:                   log,
		cn:                    vs_cn,
		shutdownC:             make(chan struct{}),
		initialPolicyFile:     initialPolicyFile,
		maxAuthDuration:       maxAuthDuration,
		bootstrapAuthDuration: bootstrapAuthDuration,
	}
	svc.policy.config = policy.InitialConfiguration
	svc.policy.policy = policy.NewEmptyPolicy()

	svc.keys.adminServiceTLSCreds = vsServerCreds
	svc.keys.visaServiceTLSCreds = vsServerCreds
	svc.keys.policyCheckingKey = privateKey.Public().(*rsa.PublicKey)
	svc.keys.tokenSigningKey = privateKey
	svc.keys.authorityCert = authorityCert

	return svc, nil
}

func mustNewRandToken() []byte {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random token: %v", err))
	}
	return buf
}

// Blocking call returns when visa service exits (see Stop func).
//
// At the time the visa service is started it is expected that the local adapter has
// already connected to a dock.
//
// Once this is started, we expect a node to contact us through the THRIFT api.
// The node should have side-loaded a visa that will allow it to talk to us over the VS port.
//
// `vsAddr` is the ZPR address of the visa service (and admin service).
// `vsPort` is the port of the THRIFT visa service.
// `adminPort` is port for HTTP admin service
// `issuerName` is used on the JWT tokens we issue.
func (s *VisaService) Start(issuerName string, vsAddr netip.Addr, vsPort uint16, adminPort uint16) error {
	s.log.Info("starting visa service", "name", issuerName, "bootstrap_auth_duration", s.bootstrapAuthDuration.String(), "max_auth_duration", s.maxAuthDuration.String())
	s.vsWg.Add(1)
	defer s.vsWg.Done()

	s.myAddr = vsAddr

	s.log.Infom("bootstrap: starting visa service")
	icfg := &VSIConfig{
		Log:                   s.log,
		CN:                    s.cn,
		VSAddr:                vsAddr,
		HopCount:              99, // TODO
		Creds:                 s.keys.visaServiceTLSCreds,
		AccessToken:           s.authToken,
		Constrainer:           NewDummyConstraintService(),
		BootstrapAuthDuration: s.bootstrapAuthDuration,
		AuthorityCert:         s.keys.authorityCert,
	}
	vsinst, err := NewVSInst(icfg)
	if err != nil {
		return err
	}
	s.service.shutdownC = make(chan struct{})
	s.service.inst = vsinst

	authenticator := auth.NewAuthenticator(s.log, s.myAddr, s.maxAuthDuration, issuerName, s.keys.tokenSigningKey)
	s.authService = authenticator
	vsinst.SetAuthSvc(authenticator)

	go func() {
		defer close(s.service.shutdownC)
		vserr := vsinst.Start(vsAddr, vsPort) // blocking call
		if vserr != nil {
			s.log.WithError(vserr).Warnm("visa service exited with error")
		}
		s.service.inst = nil
	}()

	// Pause and then check the shutdown channel to catch any configuration errors with the THRIFT setup
	// that cause immediate failure.
	time.Sleep(1 * time.Second)

	select {
	case <-s.service.shutdownC:
		s.log.Info("visa service THRIFT interface has shutdown")
		return errors.New("visa service THRIFT interface premature shutdown")
	default:
	}

	s.log.Infom("bootstrap: visa service THRIFT interface started, now installling policy")
	if err = s.installPolicyFromFile(s.initialPolicyFile, s.keys.policyCheckingKey); err != nil {
		vsinst.Stop()
		return fmt.Errorf("policy install failed: %w", err)
	}
	s.log.Infom("bootstrap: installling policy - DONE")
	return s.run(adminPort)
}

func (s *VisaService) Stop() {
	s.log.Infom("stopping visa service")
	close(s.shutdownC)
	s.vsWg.Wait()
}

// This is the tail end of the Start function.
// This blocks until error or call to Stop().
func (s *VisaService) run(adminPort uint16) error {
	adminservice := NewAdminService(s.log, s.keys.adminServiceTLSCreds, s.keys.policyCheckingKey, s)
	go func() {
		s.log.Info("starting admin service", "port", adminPort)
		if err := adminservice.StartAdminService(s.myAddr, int(adminPort)); err != nil {
			// The server always exits with an error.
			s.log.WithError(err).Info("admin service exited")
		}
	}()

	s.log.Infom("visa service running")
	var mainDidShutdown, vsDidShutdown bool

	select {
	case <-s.shutdownC:
		mainDidShutdown = true
	case <-s.service.shutdownC:
		vsDidShutdown = true
	}

	s.log.Info("stopping admin service")
	adminservice.StopAdminService()
	s.log.Info("admin service stopped")

	if !mainDidShutdown {
		s.log.Info("visa service grpc exited, stopping visa service")
		// When this function returns the Start() function will return.
	}
	if !vsDidShutdown && s.service.inst != nil {
		s.log.Info("visa service exiting, stopping grpc")
		s.service.inst.Stop()
	}

	return nil
}

// Implements an interface needed by the admin service.
func (s *VisaService) GetPolicyAndConfig() (*policy.Policy, uint64) {
	s.policy.RLock()
	defer s.policy.RUnlock()
	return s.policy.policy, s.policy.config
}

// installPolicyFromFile installs a policy from a file.
func (s *VisaService) installPolicyFromFile(fname string, pubkey *rsa.PublicKey) error {
	s.log.Info("installing policy from file", "file", fname)
	cp, err := policy.OpenContainedPolicyFile(fname, pubkey)
	if err != nil {
		return err
	}
	return s.doInstallPolicy(cp)
}

// Implements an interface needed by the admin service.
func (s *VisaService) ListVisas() []*VisaDescriptor {
	// Reach into the vsinst and rifle through the visas creating visa descriptors.
	var descriptors []*VisaDescriptor
	s.service.inst.vtable.mtx.RLock()
	defer s.service.inst.vtable.mtx.RUnlock()
	for issuerID, vtEnt := range s.service.inst.vtable.table {
		srcAddr, _ := netip.AddrFromSlice(vtEnt.v.Source)
		dstAddr, _ := netip.AddrFromSlice(vtEnt.v.Dest)
		descriptors = append(descriptors, &VisaDescriptor{
			ID:      uint64(issuerID),
			Expires: uint64(vtEnt.v.Expires),
			Source:  srcAddr.String(),
			Dest:    dstAddr.String(),
		})
	}
	return descriptors
}

// Implements an interface needed by the admin service.
func (s *VisaService) ListAdapters() []*adb.HostRecordBrief {
	return s.service.inst.actorDB.CloneToBrief()
}

func (s *VisaService) ListNodes() []*adb.NodeRecordBrief {
	return s.service.inst.actorDB.CloneNodesToBrief()
}

// Implements an interface needed by the admin service.
func (s *VisaService) ClearAllRevokes() uint32 {
	return s.authService.ClearAllRevokes()
}

// Implements an interface needed by the admin service.
func (s *VisaService) RevokeVisa(vid uint64) error {
	// Since revoking a visa just removes it from visa service table and
	// notifies network, I don't bother writing it to the in-memory
	// revocation database.
	return s.service.inst.revokeVisaByID(vid)
}

// Implements an interface needed by the admin service.
func (s *VisaService) RevokeCN(cn string) uint32 {
	// First update our memory so that if the CN shows up later it will fail.
	s.log.Info("revoke CN", "cn", cn)
	if err := s.authService.RevokeCN(cn); err != nil {
		// Hmm, store to memory failed? Log but continue.
		s.log.WithError(err).Warn("auth service failed to store CN revocation", "cn", cn)
	}

	// Then get rid of any visas involved with the CN.
	// The visa service keeps a table of visas, but to find ones for a specific actor we need
	// the ZPR addr of the actor.

	var count uint32
	actorList := s.service.inst.actorDB.GetActorsWithClaim(actor.KAttrCN, cn)
	if len(actorList) > 0 {
		count = s.service.inst.revokeVisasForActors(actorList)
		if count > 0 {
			s.log.Info("active visas removed due to revoked CN", "cn", cn, "visa_count", count)
		} else {
			s.log.Info("no active visas found for revoked CN", "cn", cn)
		}
		for _, agnt := range actorList {
			s.removeActor(agnt)
		}
	} else {
		s.log.Info("no active visas found for revoked CN", "cn", cn)
	}

	// Ideally we would tell the docking node that we are booting this actor
	// out of our system.
	return count
}

// Remove an actor from the actor DB.
// Should behave just as if de-register or disconnect were called over the vs-api.
func (s *VisaService) removeActor(agnt *actor.Actor) {
	zprAddr := agnt.GetZPRIDIfSet()
	if agnt.IsNode() {
		if prec := s.service.inst.actorDB.GetPeerRecord(zprAddr); prec != nil {
			s.service.inst.takePeerRecord(prec.APIKey)
		}
		s.service.inst.actorDB.RemoveNode(zprAddr)
		s.log.Info("node-actor has been removed", "zpr_addr", zprAddr)
	} else {
		s.service.inst.actorDB.RemoveAdapter(zprAddr)
		s.log.Info("adapter-actor has been removed", "zpr_addr", zprAddr)
	}
}

// InstallPolicy is for installing a policy supplied by an admin through our admin-service.
// Implements an interface needed by the admin service
//
// Returns (version, config_id, error)
func (s *VisaService) InstallPolicy(cp *policy.ContainedPolicy) (string, uint64, error) {
	s.log.Info("installing policy from admin")

	if err := s.doInstallPolicy(cp); err != nil {
		return "", 0, errors.New("failed to install policy on nodes")
	}

	installedPolicy, configID := s.GetPolicyAndConfig()
	pver := "(none)"
	if installedPolicy != nil {
		pver = installedPolicy.VersionAndRevision()
	}
	return pver, configID, nil
}

// doInstallPolicy actually install policy into all the visa service components, including
// communicating with any nodes.
func (s *VisaService) doInstallPolicy(cp *policy.ContainedPolicy) error {
	pp := policy.NewPolicyFromContainer(cp, s.log)
	if pp.Size() == 0 {
		return errors.New("policy is empty")
	}

	_, configID, err := s.computeVersionConfigID(pp) // this updates our local policy value
	if err != nil {
		return fmt.Errorf("policy install failed: %w", err)
	}

	s.log.Info("installing policy to visa service instance")
	return s.service.inst.InstallPolicy(configID, 0, pp)
}

// computeVersionAndConfigID updates our policy state variables.
func (s *VisaService) computeVersionConfigID(newPolicy *policy.Policy) (string, uint64, error) {
	s.policy.Lock()
	defer s.policy.Unlock()

	prevConfig, prevPolicy := s.policy.config, s.policy.policy

	// TODO: The admin service used to "test" the policy prior to install by offering it to
	//       auth and topo-manager.

	newConfig, err := ComputeConfiguration(s.log, prevPolicy, prevConfig, newPolicy)
	if err != nil {
		return "", 0, fmt.Errorf("configuration processing failed: %w", err)
	}

	s.policy.policy = newPolicy
	s.policy.config = newConfig

	// TODO: Node writes the policy to a file, should we?

	return newPolicy.VersionAndRevision(), newConfig, nil
}

const (
	configYearX  = 1000000000
	configMonthX = 10000000
	configDayX   = 100000
)

// The rather tricky job of determining if a proposed policy change requires a configuration change.
// Capitalized so I can test it.
func ComputeConfiguration(log logr.Logger, curPolicy *policy.Policy, curConfig uint64, proposedPolicy *policy.Policy) (uint64, error) {

	needsNewConfig := false

	// The initial config value is reserved for the initial, empty policy.
	// So it's easy when we are adding a non-empty policy
	if curConfig == policy.InitialConfiguration && (proposedPolicy != nil) && proposedPolicy.Size() > 0 {
		log.Info("transition to non-empty policy detected")
		needsNewConfig = true
		goto checkdone
	}
	if !bytes.Equal(curPolicy.GetDatasourceHash(), proposedPolicy.GetDatasourceHash()) {
		log.Info("policy datasource configuration change detected")
		needsNewConfig = true
		goto checkdone
	}
	if !bytes.Equal(curPolicy.GetTopologyHash(), proposedPolicy.GetTopologyHash()) {
		log.Info("policy topology configuration change detected")
		needsNewConfig = true
		goto checkdone
	}
	if !proposedPolicy.GetServiceMesh().Includes(curPolicy.GetServiceMesh()) {
		log.Info("service mesh configuration change detected")
		needsNewConfig = true
		goto checkdone
	}
	if !curPolicy.IsConnectCompatibleWith(proposedPolicy) {
		log.Info("connect policy restriction detected")
		needsNewConfig = true
		goto checkdone
	}

checkdone:
	if needsNewConfig {
		var newStamp, counter uint64
		now := time.Now().UTC()
		newStamp = (uint64(now.Year()) * configYearX) + (uint64(now.Month()) * configMonthX) + (uint64(now.Day()) * configDayX)
		if newStamp/configDayX != curConfig/configDayX {
			counter = 1
		} else {
			counter = (curConfig % configDayX) + 1
		}
		newConfig := newStamp + counter
		log.Info("bumping configuration", "old_config", curConfig, "new_config", newConfig)
		if newConfig > math.MaxInt64 {
			// TODO: problem to solve another day. Our vsapi visa struct only accepts int64.
			panic("ran out of configuration ID numbers")
		}
		return newConfig, nil
	}
	// Else, keep config the same
	return curConfig, nil
}

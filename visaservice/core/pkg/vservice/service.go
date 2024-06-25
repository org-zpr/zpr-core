package vservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vsapi"

	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/auth"

	"zpr.org/vsx/polio"
)

type VisaService struct {
	log               logr.Logger
	myAddr            netip.Addr // visa serice ZPR contact address
	authToken         []byte
	vsWg              sync.WaitGroup
	shutdownC         chan struct{} // when closed our run() fuction will return
	initialPolicyFile string
	authService       auth.AuthService
	maxAuthDuration   time.Duration

	keys struct {
		policyCheckingKey    *rsa.PublicKey                   // for checking policy signature
		adminServiceTLSCreds credentials.TransportCredentials // admins service TLS
		visaServiceTLSCreds  credentials.TransportCredentials // thrift service TLS
		tokenSigningKey      *rsa.PrivateKey                  // for signing JWT tokens
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

func NewVisaService(initialPolicyFile string, privateKey *rsa.PrivateKey, vsServerCreds credentials.TransportCredentials, maxAuthDuration time.Duration, log logr.Logger) (*VisaService, error) {
	if _, err := os.Stat(initialPolicyFile); err != nil {
		return nil, fmt.Errorf("policy file stat error: %w", err)
	}
	svc := &VisaService{
		log:               log,
		shutdownC:         make(chan struct{}),
		initialPolicyFile: initialPolicyFile,
		maxAuthDuration:   maxAuthDuration,
	}
	svc.policy.config = policy.InitialConfiguration
	svc.policy.policy = policy.NewEmptyPolicy()

	svc.keys.adminServiceTLSCreds = vsServerCreds
	svc.keys.visaServiceTLSCreds = vsServerCreds
	svc.keys.policyCheckingKey = privateKey.Public().(*rsa.PublicKey)
	svc.keys.tokenSigningKey = privateKey

	svc.keys.adminServiceTLSCreds = vsServerCreds
	svc.keys.visaServiceTLSCreds = vsServerCreds
	svc.keys.policyCheckingKey = privateKey.Public().(*rsa.PublicKey)
	svc.keys.tokenSigningKey = privateKey

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
// `vsPort` is the port of the visa service.
// `issuerName` is used on the JWT tokens we issue.
func (s *VisaService) Start(issuerName string, vsAddr netip.Addr, vsPort uint16) error {
	s.log.Info("starting visa service", "name", issuerName)
	s.vsWg.Add(1)
	defer s.vsWg.Done()

	s.myAddr = vsAddr

	s.log.Infom("bootstrap: starting visa service")
	icfg := &VSIConfig{
		Log:         s.log,
		HopCount:    99, // TODO
		Creds:       s.keys.visaServiceTLSCreds,
		AccessToken: s.authToken,
		Constrainer: NewDummyConstraintService(),
	}
	vsinst, err := NewVSInst(icfg)
	if err != nil {
		return err
	}
	s.service.shutdownC = make(chan struct{})
	s.service.inst = vsinst

	authenticator := auth.NewAuthenticator(s.log, s.myAddr, s.maxAuthDuration, issuerName, s.keys.tokenSigningKey)
	authenticator.SetRevocationService(&auth.DummyRecovationService{})
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
	if err = s.installPolicyFromFile(s.initialPolicyFile, s.keys.policyCheckingKey, nil); err != nil {
		vsinst.Stop()
		return fmt.Errorf("policy install failed: %w", err)
	}
	s.log.Infom("bootstrap: installling policy - DONE")
	return s.run()
}

func (s *VisaService) Stop() {
	s.log.Infom("stopping visa service")
	close(s.shutdownC)
	s.vsWg.Wait()
}

// This is the tail end of the Start function.
// This blocks until error or call to Stop().
func (s *VisaService) run() error {

	adminservice := NewAdminService(s.log, s.keys.adminServiceTLSCreds, s.keys.policyCheckingKey, s)

	go func() {
		s.log.Info("starting admin service", "port", AdminPort)
		if err := adminservice.StartGrpc(s.myAddr, AdminPort); err != nil {
			s.log.WithError(err).Warn("admin service exited with error")
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
	adminservice.StopGrpc()
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

// installPolicyFromFile installs a policy from a file.
//
// TODO: The visa service needs to be able to install a new policy form an admin.
// So there must be an RPC call to visa service that an admin can use to install a policy.
//
// If `nodeAddrs` are given we also create visas for those nodes.  Note this is older code
// and may not be needed in new ref-impl.  Can leave this empty.
func (s *VisaService) installPolicyFromFile(fname string, pubkey *rsa.PublicKey, nodeAddrs []netip.Addr) error {
	s.log.Info("installing policy from file", "file", fname)
	cp, err := polio.OpenContainedPolicyFile(fname, pubkey)
	if err != nil {
		return err
	}
	return s.installPolicyWithVisasForNodes(true, cp, nodeAddrs)
}

// Implements an interface needed by the admin service.
func (s *VisaService) GetPolicyAndConfig() (*policy.Policy, uint64) {
	s.policy.RLock()
	defer s.policy.RUnlock()
	return s.policy.policy, s.policy.config
}

// InstallPolicy is for installing a policy supplied by an admin through our admin-service.
//
//	 TODO: This is also sending visas over to the node, not sure if we need to our not.
//		Feels like we should use our existing push system to renew all the important visas
//		before sending.  Surely we did something like that in the past.
//
// Returns (version, config_id, error)
func (s *VisaService) InstallPolicy(cp *polio.ContainedPolicy) (string, uint64, error) {
	s.log.Info("installing policy from admin")

	// TODO: Presumably we need to install on all our known nodes.
	//       What does a node need from the policy anyway?  Just topology I think.

	// There's plenty of room for error here.  We used to use raft to distribute
	// policy to nodes.  Needs more thought.

	nodes := s.service.inst.GetNodeList()
	if err := s.installPolicyWithVisasForNodes(false, cp, nodes); err != nil {
		return "", 0, errors.New("failed to install policy on nodes")
	}

	installedPolicy, configID := s.GetPolicyAndConfig()
	pver := "(none)"
	if installedPolicy != nil {
		pver = installedPolicy.VersionAndRevision()
	}
	return pver, configID, nil
}

// `nodeAddrs` are ZPR addresses of nodes.
func (s *VisaService) installPolicyWithVisasForNodes(bootstrap bool, cp *polio.ContainedPolicy, nodeAddrs []netip.Addr) error {
	pp := policy.NewPolicyFromContainer(cp, s.log)
	if pp.Size() == 0 {
		return errors.New("policy is empty")
	}

	pversion, configID, err := s.computeVersionConfigID(pp) // this updates our local policy value
	if err != nil {
		return fmt.Errorf("policy install failed: %w", err)
	}

	s.log.Info("installing policy to auth service")
	s.authService.InstallPolicy(configID, 0, pp)

	s.log.Info("installing policy to visa service")
	s.service.inst.InstallPolicy(configID, 0, pp)

	// To send this over the wire we want it zipped.
	/* OFF - we don't yet know how or why to send policy in Ref Impl.
	format := cp.Policy.SerialVersion
	gzPolicy, err := libvisa.Compress(cp.Container)
	if err != nil {
		return fmt.Errorf("failed to compress policy: %w", err)
	}
	*/

	// Create a visa-service visa so NODE can talk to US.
	var visas []*vsapi.VisaHop

	for _, nodeAddr := range nodeAddrs {
		s.log.Info("generating a new visa-service visa for the node->VS", "node_addr_src", nodeAddr, "vs_addr_dest", s.myAddr)
		pktData := snip.NewTCPConnect(nodeAddr, 0, s.myAddr, VisaServicePort)
		vsr, err := s.service.inst.doRequestVisa(context.Background(), nodeAddr, pktData, 0, pp.VersionNumber())
		if err != nil {
			s.log.WithError(err).Warn("failed to generate a visa-service visa for the node", "node_addr", nodeAddr)
		} else if vsr.Status != vsapi.StatusCode_SUCCESS {
			s.log.Warn("failed to generate a visa-service visa for the node", "node", nodeAddr, "reason", vsr.Reason)
		} else {
			visas = append(visas, vsr.Visa)
		}
	}

	s.log.Info("(TODO) now send policy to node", "version", pversion, "configID", configID)
	// TODO:
	//   The prototype used the visa-support-service to send a policy to the node.
	//   Plus it ised to also send along a visa.  Instead we should use our polling system.
	//   AND the node doesn't need the whole policy. So we need to figure out what it needs and
	//   figure out how the visa-service tells node about it.
	//

	if len(visas) > 0 {
		pr := vsapi.PollResponse{
			Visas: visas,
		}
		// TODO: Should we set hopcount to 1?
		s.service.inst.PushVisa(&pr)
	}

	return nil
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
		return newConfig, nil
	}
	// Else, keep config the same
	return curConfig, nil
}

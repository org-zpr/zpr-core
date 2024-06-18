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
	"google.golang.org/protobuf/proto"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vsapi"

	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/vservice/auth"
	"zpr.org/vsx/snio/vsio"

	"zpr.org/vsx/polio"
)

type VisaService struct {
	log               logr.Logger
	myAddr            netip.Addr // visa serice contact address
	authToken         []byte
	vsWg              sync.WaitGroup
	visaServiceCreds  credentials.TransportCredentials
	shutdownC         chan struct{} // when closed our run() fuction will return
	initialPolicyFile string
	authService       auth.AuthService
	privateKey        *rsa.PrivateKey
	maxAuthDuration   time.Duration
	agentSigningKey   *rsa.PrivateKey

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
		myAddr:            netip.MustParseAddr(VisaServiceAddress),
		visaServiceCreds:  vsServerCreds,
		shutdownC:         make(chan struct{}),
		initialPolicyFile: initialPolicyFile,
		privateKey:        privateKey,
		maxAuthDuration:   maxAuthDuration,
	}
	svc.policy.config = policy.InitialConfiguration
	svc.policy.policy = policy.NewEmptyPolicy()

	// Generate a key that this visa service will use to sign agent identities.
	if pk, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	} else {
		svc.agentSigningKey = pk
	}

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
// already connected to a dock.  The visa service will attempt to connect to the
// node.
//
// The adapater has a keypair that is verified by the node.
//
// `nodeAddr` the node to dock to.
// `vssPort` port on node running the visa support service.
// `vsPort` local port to listen on (at default visa service address) for node connections to visa service.
func (s *VisaService) Start(nodeAddr netip.Addr, nodeName, vsTlsName string, vsPort int) error {
	s.log.Info("starting visa service", "tls_name", vsTlsName)
	vsAddr := netip.MustParseAddr(VisaServiceAddress)
	s.vsWg.Add(1)
	defer s.vsWg.Done()

	s.log.Infom("bootstrap: starting visa service")
	icfg := &VSIConfig{
		Log:             s.log,
		HopCount:        99,                         // TODO
		NodeName:        "_VISA_SERVICE_NODE_NAME_", // TODO: What is this for?
		Creds:           s.visaServiceCreds,
		AccessToken:     s.authToken,
		AgentSigningKey: s.agentSigningKey,
		Constrainer:     NewDummyConstraintService(),
	}
	vsinst, err := NewVSInst(icfg)
	if err != nil {
		return err
	}
	s.service.shutdownC = make(chan struct{})
	s.service.inst = vsinst

	authenticator := auth.NewAuthenticator(s.log, s.myAddr, s.maxAuthDuration, nodeName, s.privateKey)
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

	time.Sleep(1 * time.Second) // take a breath

	s.log.Infom("bootstrap: installling policy using support service")
	if err = s.installPolicyFromFile(s.initialPolicyFile, nil, nodeAddr); err != nil {
		vsinst.Stop()
		return fmt.Errorf("policy install failed: %w", err)
	}
	s.log.Infom("bootstrap: installling policy using support service - DONE")

	// - wait for node registration with visa service...
	ticker := time.NewTicker(2 * time.Second)
	for {
		s.log.Info("bootstrap: waiting for node registration", "from_addr", nodeAddr)
		if vsinst.HasRegisteredNode(nodeAddr) {
			break
		}
		select {
		case <-s.shutdownC:
			ticker.Stop()
			return fmt.Errorf("no registration from node")
		case <-s.service.shutdownC:
			ticker.Stop()
			return fmt.Errorf("visa service shutdown before node registration")
		case <-ticker.C:
			continue
		}
	}
	ticker.Stop()
	s.log.Info("bootstrap: node registration received")

	// - install vs visas
	s.log.Infom("bootstrap: NOW NO PUSH POLICY TO OUR NODE .... HOW? (TODO)")
	s.log.Infom("bootstrap: ...")

	s.log.Infom("bootstrap completed")
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

	adminservice := NewAdminService(s.log, s.visaServiceCreds, s.privateKey.Public().(*rsa.PublicKey), s)

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
//
// New Policy install used to be the job of the admin service. But now really the visa
// service needs to start the process and it will direct the node through the visa-support
// interface.
//
// So there must be an RPC call to visa service that an admin can use to install a policy. (TODO)
func (s *VisaService) installPolicyFromFile(fname string, pubkey *rsa.PublicKey, nodeAddr netip.Addr) error {
	s.log.Info("installing policy from file", "file", fname)
	cp, err := polio.OpenContainedPolicyFile(fname, pubkey)
	if err != nil {
		return err
	}
	return s.installPolicyWithVisasForNode(true, cp, nodeAddr)
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

	nodeCount, failCount := 0, 0

	for _, naddr := range s.service.inst.GetNodeList() {
		nodeCount++
		if err := s.installPolicyWithVisasForNode(false, cp, naddr); err != nil {
			failCount++
		}
	}
	if nodeCount == failCount {
		return "", 0, errors.New("failed to install policy on any node")
	}
	if failCount > 1 {
		s.log.Warn("failed to install policy on some nodes", "failed", failCount, "total", nodeCount)
	}

	installedPolicy, configID := s.GetPolicyAndConfig()
	pver := "(none)"
	if installedPolicy != nil {
		pver = installedPolicy.VersionAndRevision()
	}
	return pver, configID, nil
}

func (s *VisaService) installPolicyWithVisasForNode(bootstrap bool, cp *polio.ContainedPolicy, nodeAddr netip.Addr) error {
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
	var visas []*vsio.Visa
	{
		s.log.Info("generating a new visa-service visa for the node->VS", "node_addr_src", nodeAddr, "vs_addr_dest", s.myAddr)
		pktData := snip.NewTCPConnect(nodeAddr, 0, s.myAddr, VisaServicePort)
		vsr, err := s.service.inst.doRequestVisa(context.Background(), nodeAddr, pktData, 0, pp.VersionNumber())
		if err != nil {
			s.log.WithError(err).Warn("failed to generate a visa-service visa for the node")
		} else if !vsr.Success {
			s.log.Warn("failed to generate a visa-service visa for the node", "reason", vsr.ErrorMsg)
		} else {
			visas = append(visas, vsr.Visa.Visa)
		}
	}

	s.log.Info("(TODO) now send policy to node", "version", pversion, "configID", configID)
	// TODO:
	//   The prototype used the visa-support-service to send a policy to the node.
	//   Plus it ised to also send along a visa.  Instead we should use our polling system.
	//   AND the node doesn't need the whole policy. So we need to figure out what it needs and
	//   figure out how the visa-service tells node about it.
	//

	// For now dumping a visa in the mailbox.

	var vsapiVisas []*vsapi.VisaHop
	for _, sniov := range visas {
		pbuf, err := proto.Marshal(sniov)
		if err != nil {
			vsapiVisas = append(vsapiVisas, &vsapi.VisaHop{VisaPb: pbuf, HopCount: 1})
		} else {
			s.log.WithError(err).Error("failed to marshal a visa -- skipping", "id", sniov.IssuerId)
		}
	}
	if len(vsapiVisas) > 0 {
		pr := vsapi.PollResponse{
			Visas: vsapiVisas,
		}
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

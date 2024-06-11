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
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"

	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/polio"
	"zpr.org/vs/pkg/snio/vsio"
	"zpr.org/vs/pkg/vservice/auth"
)

type VisaService struct {
	log               logr.Logger
	myAddr            netip.Addr // visa serice contact address
	myTetherAddr      netip.Addr // tether address assigned to us by dock (for use during bootstrap)
	authToken         []byte
	vsWg              sync.WaitGroup
	supportSvc        *VSSClient
	supportCreds      credentials.TransportCredentials
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

func NewVisaService(initialPolicyFile string, privateKey *rsa.PrivateKey, vssClientCreds, vsServerCreds credentials.TransportCredentials, maxAuthDuration time.Duration, log logr.Logger) (*VisaService, error) {
	if _, err := os.Stat(initialPolicyFile); err != nil {
		return nil, fmt.Errorf("policy file stat error: %w", err)
	}
	svc := &VisaService{
		log:               log,
		myAddr:            netip.MustParseAddr(VisaServiceAddress),
		supportCreds:      vssClientCreds,
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
// The visa service also does some sort of authentication with the nodes support service.
// (which is grpc).
//
// `nodeAddr` the node to dock to.
// `vssPort` port on node running the visa support service.
// `vsPort` local port to listen on (at default visa service address) for node connections to visa service.
func (s *VisaService) Start(nodeAddr netip.Addr, nodeName, vsTlsName string, vssPort, vsPort int) error {
	s.log.Info("starting visa service", "tls_name", vsTlsName)
	vsAddr := netip.MustParseAddr(VisaServiceAddress)
	s.vsWg.Add(1)
	defer s.vsWg.Done()

	s.log.Info("connecting to node visa support service", "addr", nodeAddr, "port", vssPort)
	client, err := NewVSSClient(s.log, nodeAddr, vssPort, nodeName, s.supportCreds, &s.agentSigningKey.PublicKey)
	if err != nil {
		return err
	}
	s.supportSvc = client

	if err := s.supportSvc.Hello(); err != nil {
		s.log.WithError(err).Warnm("failed to connect to node")
		return err
	}
	s.authToken = mustNewRandToken()
	authResp, err := s.supportSvc.AuthRequest(vsTlsName, s.authToken)
	if err != nil {
		s.log.WithError(err).Warnm("failed to authenticate with node")
		return err
	}
	s.myTetherAddr, _ = netip.AddrFromSlice(authResp.TetherAddr)
	s.log.Info("connection to support service successful", "my_tether_addr", s.myTetherAddr)
	s.log.Infom("bootstrap: starting visa service grpc service")
	icfg := &VSIConfig{
		Log:             s.log,
		HopCount:        99,                         // TODO
		NodeName:        "_VISA_SERVICE_NODE_NAME_", // TODO: What is this for?
		Creds:           s.visaServiceCreds,
		AccessToken:     s.authToken,
		AgentSigningKey: s.agentSigningKey,
		Directory:       s.supportSvc,
		Constrainer:     s.supportSvc,
	}
	vsinst, err := NewVSInst(icfg)
	if err != nil {
		return err
	}
	s.service.shutdownC = make(chan struct{})
	s.service.inst = vsinst

	authenticator := auth.NewAuthenticator(s.log, s.myAddr, s.maxAuthDuration, nodeName, s.privateKey)
	authenticator.SetRevocationService(s.supportSvc)
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

	// TODO: Did I move over the configuration logic (ie, code that decides on a new configuraiton ID)??  Was in zprn/admin_service

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
	s.log.Info("bootstrap: adding node to our pollers list", "addr", nodeAddr)
	vsinst.AddNode(nodeAddr)

	// - install vs visas
	s.log.Infom("bootstrap: **TODO** installing fresh VSS visas using visa service PUSH")
	s.log.Infom("bootstrap: ...")

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
	err := s.installPolicyWithVisasForNode(false, cp, s.supportSvc.NodeAddr)
	if err != nil {
		return "", 0, err
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
	format := cp.Policy.SerialVersion
	gzPolicy, err := libvisa.Compress(cp.Container)
	if err != nil {
		return fmt.Errorf("failed to compress policy: %w", err)
	}

	// Create a visa-service visa so NODE can talk to US.
	// Create a visa-support-service visa so that WE can talk to NODE.
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
	{
		s.log.Info("generating a new visa-support-service visa for the VS->node", "vs_addr_src", s.myAddr, "node_addr_dest", nodeAddr)
		pktData := snip.NewTCPConnect(s.myAddr, 0, nodeAddr, VisaSupportServicePort)
		vsr, err := s.service.inst.doRequestVisa(context.Background(), s.myTetherAddr, pktData, 0, pp.VersionNumber())
		if err != nil {
			s.log.WithError(err).Warn("failed to generate a visa-service visa for the node")
		} else if !vsr.Success {
			s.log.Warn("failed to generate a visa-service visa for the node", "reason", vsr.ErrorMsg)
		} else {
			visas = append(visas, vsr.Visa.Visa)
		}
	}

	s.log.Info("sending policy to node support service", "version", pversion, "configID", configID)
	resp, err := s.supportSvc.InstallPolicy(bootstrap, format, gzPolicy, configID, visas)
	if err != nil {
		return err
	}
	s.log.Info("support service returns OK", "version", resp.Version, "config_id", resp.ConfigId)
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

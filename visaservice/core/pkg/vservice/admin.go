package vservice

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vsx/snio/admin"

	"zpr.org/vsx/polio"
)

// 'admin.go' implements the parts of the admin service applicable to the visa service.

// Visa Service API that admin service needs to do its job.
type VSApi interface {
	GetPolicyAndConfig() (*policy.Policy, uint64)
	InstallPolicy(*polio.ContainedPolicy) (string, uint64, error) // returns (version, config_id, error)
}

type AdminService struct {
	admin.UnimplementedAdminServer

	log    logr.Logger
	creds  credentials.TransportCredentials
	pubkey *rsa.PublicKey // for checking policy signature
	vsi    VSApi

	installMtx sync.Mutex

	service struct {
		localAddr netip.Addr // local service address
		gsrvWg    sync.WaitGroup
		gsrv      *grpc.Server
	}
}

// NewAdminService creates the gRPC admin service -- you must call blocking function StartGrpc to start the service.
//
// `creds` is the transport credentials for the gRPC server.
// `pubkey` is the public key used to verify the signature of the policy.
func NewAdminService(log logr.Logger, creds credentials.TransportCredentials, pubkey *rsa.PublicKey, vsi VSApi) *AdminService {
	return &AdminService{
		log:    log,
		creds:  creds,
		pubkey: pubkey,
		vsi:    vsi,
	}
}

// Blocking function
func (svc *AdminService) StartGrpc(listenAddr netip.Addr, port int) error {
	svc.service.localAddr = listenAddr
	svc.service.gsrvWg.Add(1)
	defer svc.service.gsrvWg.Done()
	var conStr string
	if listenAddr.Is6() {
		conStr = fmt.Sprintf("[%v]:%d", listenAddr.String(), port)
	} else {
		if listenAddr.IsUnspecified() {
			svc.log.Warn("admin service interface is unwisely configured to use IPv4 localhost")
		}
		conStr = fmt.Sprintf("%v:%d", listenAddr.String(), port)
	}
	lis, err := net.Listen("tcp", conStr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	opts := []grpc.ServerOption{
		grpc.Creds(svc.creds),
	}
	svc.service.gsrv = grpc.NewServer(opts...)
	admin.RegisterAdminServer(svc.service.gsrv, svc)
	svc.log.Infof("admin service starts on %v", conStr)
	if err = svc.service.gsrv.Serve(lis); err != nil {
		svc.log.Errorf("admin service exited with error: %v", err)
		return err
	}
	svc.log.Info("admin service exiting")
	return nil
}

// Stop server, blocking until complete.
func (svc *AdminService) StopGrpc() {
	if svc.service.gsrv != nil {
		svc.service.gsrv.Stop()
		svc.service.gsrvWg.Wait()
		svc.service.gsrv = nil
	}
}

func peerAddrFromCtx(ctx context.Context) netip.Addr {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return netip.Addr{}
	}
	// peer.Addr is a net.Addr
	ap, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr()
}

func (svc *AdminService) Fetch(ctx context.Context, fr *admin.FetchRequest) (*admin.FetchResponse, error) {
	reqIP := peerAddrFromCtx(ctx)
	svc.log.Info("admin: fetch request", "peer", reqIP)

	pcy, configID := svc.vsi.GetPolicyAndConfig()
	if pcy == nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy not found at %d", fr.GetConfigId())
	}

	zbuf, err := libvisa.Compress(pcy.Export())
	if err != nil {
		svc.log.WithError(err).Error("admin failed to serialized policy, aborting fetch request")
		return nil, status.Error(codes.Internal, "serialization failed")
	}

	svc.log.Debug("admin fetch request processed successfully", "config", configID, "version", pcy.Version())
	resp := &admin.FetchResponse{
		Version:         pcy.Version(),
		Format:          pcy.GetSerialVersion(),
		PolicyContainer: zbuf, // TODO: Perhaps version and format could be attributes of PolicyContainer?
		ConfigId:        configID,
	}
	return resp, nil
}

func (svc *AdminService) List(ctx context.Context, lr *admin.ListRequest) (*admin.ListResponse, error) {
	reqIP := peerAddrFromCtx(ctx)
	svc.log.Info("admin: list request", "peer", reqIP)
	pcy, configID := svc.vsi.GetPolicyAndConfig()
	pver := "(none)"
	if pcy != nil {
		pver = pcy.VersionAndRevision()
	}
	resp := admin.ListResponse{}
	resp.List = append(resp.List, &admin.ListResponseEl{
		ConfigId: configID,
		Version:  pver,
	})
	return &resp, nil
}

func (svc *AdminService) Install(ctx context.Context, rr *admin.InstallRequest) (*admin.InstallResponse, error) {
	reqIP := peerAddrFromCtx(ctx)
	svc.log.Info("admin: install request", "peer", reqIP)

	// TODO: Is our grpc server multi-threaded?  Not sure so we are locking here
	//       to allow only one install to run at a time.
	svc.installMtx.Lock()
	defer svc.installMtx.Unlock()

	currentP, _ := svc.vsi.GetPolicyAndConfig()
	if rr.GetVersion() != "" {
		if currentP != nil && currentP.Version() != rr.GetVersion() {
			return nil, status.Errorf(codes.FailedPrecondition, "expected version mismatch")
		}
	}
	if rr.GetFormat() != polio.SerialVersion {
		return nil, status.Errorf(codes.FailedPrecondition,
			fmt.Sprintf("incompatible policy serialization schema: expected %d, got %d", polio.SerialVersion, rr.GetFormat()))
	}

	polcont, err := libvisa.Decompress(rr.GetPolicyContainer())
	if err != nil {
		svc.log.WithError(err).Error("admin failed to unmarshal policy byndle, policy install aborted")
		return nil, status.Errorf(codes.InvalidArgument, "error unmarshalling policy")
	}
	containedPol, err := polio.OpenContainedPolicy(polcont, svc.pubkey)
	if err != nil {
		svc.log.WithError(err).Error("admin failed to open policy container")
		return nil, status.Errorf(codes.InvalidArgument, "container error")
	}
	pversion, configID, err := svc.vsi.InstallPolicy(containedPol)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "policy install failed: %v", err)
	}
	return &admin.InstallResponse{
		Version:  pversion,
		ConfigId: configID,
	}, nil
}

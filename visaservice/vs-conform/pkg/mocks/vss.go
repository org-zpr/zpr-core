package mocks

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"go.uber.org/zap"
	"zpr.org/vsapi"
)

// Mock up of visa support service
type Vss struct {
	svc  *VssSvc
	log  *zap.SugaredLogger
	plog *PLogger

	Policies chan (*vsapi.PolicyInfo)
	Visas    chan (*vsapi.VisaHop)
	Revokes  chan (*vsapi.VisaRevocation)
}

// Create a new VSS and start listening for requests.
// Call Close() to stop the server.
func NewVss(listenAddr netip.AddrPort, lgr *zap.Logger) (*Vss, error) {

	vss := &Vss{
		log:  lgr.Sugar(),
		plog: NewPLogger("vss", "vs"),

		Policies: make(chan (*vsapi.PolicyInfo), 32),
		Visas:    make(chan (*vsapi.VisaHop), 32),
		Revokes:  make(chan (*vsapi.VisaRevocation), 32),
	}

	svc, err := newVssClient(listenAddr, vss)
	if err != nil {
		return nil, err
	}

	vss.svc = svc

	go func() {
		ll := lgr.Sugar()
		ll.Infow("starting visa support service", "addr", listenAddr)
		if err := svc.server.Serve(); err != nil {
			ll.Errorw("VSS thrift server exits with error", "error", err)
		} else {
			ll.Info("VSS thrift server exits normally")
		}
	}()

	return vss, nil
}

// Shuts down the VSS server.
func (v *Vss) Close() {
	v.svc.Close()
}

// Drains the policies, visas, and revocations channels.
func (v *Vss) Reset() {
	v.log.Info("VSS: reset")
	for {
		select {
		case <-v.Policies:
		case <-v.Visas:
		case <-v.Revokes:
		default:
			return
		}
	}
}

func (v *Vss) NetworkPolicyInstalled(ctx context.Context, pi *vsapi.PolicyInfo) error {
	v.plog.Log(Rev, "network_policy_installed")
	v.log.Infow("VSS: NetworkPolicyInstalled", "pi", pi)
	select {
	case v.Policies <- pi: // ok
	default:
		v.log.Warn("VSS: NetworkPolicyInstalled: channel full")
	}
	return nil
}

func (v *Vss) InstallVisas(ctx context.Context, visas []*vsapi.VisaHop) error {
	v.plog.Log(Rev, "install_visas")
	v.log.Infow("VSS: InstallVisas", "visa_count", len(visas))
	for _, vsa := range visas {
		select {
		case v.Visas <- vsa: // ok
		default:
			v.log.Warn("VSS: InstallVisas: channel full")
		}
	}
	return nil
}

func (v *Vss) RevokeVisas(ctx context.Context, revokes []*vsapi.VisaRevocation) error {
	v.plog.Log(Rev, "revoke_visas")
	v.log.Infow("VSS: RevokeVisas", "revoke_count", len(revokes))
	for _, vr := range revokes {
		select {
		case v.Revokes <- vr: // ok
		default:
			v.log.Warn("VSS: RevokeVisas: channel full")
		}
	}
	return nil
}

// var defaultCtx = context.Background()

type VssSvc struct {
	transport thrift.TServerTransport
	server    *thrift.TSimpleServer
}

func newVssClient(addr netip.AddrPort, handler *Vss) (*VssSvc, error) {
	if !addr.Addr().Is4() {
		return nil, fmt.Errorf("VSS address must be IPv4: %s", addr)
	}
	cfg := &thrift.TConfiguration{
		ConnectTimeout: 5 * time.Second,
		SocketTimeout:  5 * time.Second,
	}

	protocolFac := thrift.NewTBinaryProtocolFactoryConf(nil)
	transportFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), cfg)

	var transport thrift.TServerTransport
	var err error
	transport, err = thrift.NewTServerSocket(addr.String())
	if err != nil {
		return nil, fmt.Errorf("thrift NewTServerSocket failed: %w", err)
	}

	processor := vsapi.NewVisaSupportProcessor(handler)
	server := thrift.NewTSimpleServer4(processor, transport, transportFac, protocolFac)

	return &VssSvc{
		transport: transport,
		server:    server,
	}, nil
}

func (c *VssSvc) Close() {
	c.server.Stop()
	c.transport.Close()
}

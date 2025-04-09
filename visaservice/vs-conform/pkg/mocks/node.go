package mocks

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"zpr.org/vsapi"

	"github.com/apache/thrift/lib/go/thrift"
	"go.uber.org/zap"
)

// Node is a mockup node for testing visa service.
type Node struct {
	zlog     *zap.SugaredLogger
	plog     *PLogger
	vsAddr   netip.AddrPort
	vssAddr  netip.AddrPort
	vss      *Vss
	apiKey   string
	connects []netip.Addr // zpr addresses of connects seen in authorize-connect
}

func NewNode(vsAddr netip.AddrPort, lgr *zap.Logger, vssAddr netip.AddrPort) (*Node, error) {
	vss, err := NewVss(vssAddr, lgr)
	if err != nil {
		return nil, fmt.Errorf("failed to init VSS: %w", err)
	}
	return &Node{
		zlog:    lgr.Sugar(),
		plog:    NewPLogger("node", "vs"),
		vsAddr:  vsAddr,
		vssAddr: vssAddr,
		vss:     vss,
	}, nil
}

func (n *Node) SetPlogEnabled(enabled bool) {
	n.plog.enabled = enabled
}

func (n *Node) HasApiKey() bool {
	return n.apiKey != ""
}

func (n *Node) GetApiKey() string {
	return n.apiKey
}

func (n *Node) Hello() (*vsapi.HelloResponse, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	n.zlog.Info("node->vs: HELLO")
	n.plog.Log(Fwd, "hello")
	resp, err := cli.Hello()
	if err != nil {
		return nil, fmt.Errorf("hello failed: %w", err)
	}
	n.plog.Log(Rev, "hello_response")
	n.zlog.Infow("hello succeeds", "sid", resp.SessionID)
	return resp, nil
}

// If we get an API key, we keep it in our state.
// If VSS is enabled we set the VSS addr in the request if it is blank.
func (n *Node) Authenticate(chalresp *vsapi.NodeAuthRequest) (string, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return "", err
	}
	defer cli.Close()
	if chalresp.VssService == "" {
		if n.vss != nil {
			chalresp.VssService = n.vssAddr.String()
		} else {
			panic("VSS service address must be set") // programmer error
		}
	}
	n.plog.Log(Fwd, "authenticate")
	n.zlog.Info("node->vs: AUTHENTICATE")
	apiKey, err := cli.client.Authenticate(defaultCtx, chalresp)
	if err != nil {
		n.zlog.Infow("authenticate failed", "error", err)
		return "", fmt.Errorf("authenticate failed: %w", err)
	} else {
		n.plog.Log(Rev, "node_auth_request")
		n.apiKey = apiKey
		n.zlog.Infow("authenticate succeeds", "api_key", apiKey)
	}
	return apiKey, nil
}

// may be empty string.
func (n *Node) GetAPIKey() string {
	return n.apiKey
}

// Deregister the passed apikey, or pass empty string to de-register the one in our state.
func (n *Node) DeRegister(apikey string) error {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return err
	}
	defer cli.Close()
	n.plog.Log(Fwd, "de-register")
	n.zlog.Info("node->vs: DE-REGISTER")
	if apikey == "" {
		apikey = n.apiKey
		n.apiKey = ""
	}
	if apikey == "" {
		return fmt.Errorf("invalid empty apikey passed")
	}
	cli.client.DeRegister(defaultCtx, apikey)
	return nil
}

func (n *Node) AuthorizeConnect(apikey string, req *vsapi.ConnectRequest) (*vsapi.ConnectResponse, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	n.plog.Log(Fwd, "authorize_connect")
	n.zlog.Infow("node->vs: AUTHORIZE CONNECT")
	resp, err := cli.client.AuthorizeConnect(defaultCtx, apikey, req)
	if err != nil {
		n.zlog.Infow("authorize connect failed", "error", err)
		return nil, fmt.Errorf("authorize-connect failed: %w", err)
	}
	n.plog.Log(Rev, "connect_response")
	if resp.Status == vsapi.StatusCode_SUCCESS {
		if zaddr, ok := netip.AddrFromSlice(resp.Actor.ZprAddr); ok {
			n.zlog.Infow("authorize connect succeeds", "zpr_addr", zaddr)
			n.connects = append(n.connects, zaddr)
		} else {
			n.zlog.Infow("authorize connect succeeds", "zpr_addr", "nil") // this is error I think and should be checked in a test.
		}
	} else {
		n.zlog.Infow("authorize connect returns non-success", "status", resp.Status)
	}
	return resp, nil
}

func (n *Node) RequestVisa(apikey string, srcTether netip.Addr, l3Type int, pkt []byte) (*vsapi.VisaResponse, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	n.plog.Log(Fwd, "request_visa")
	n.zlog.Info("node->vs: REQUEST VISA")
	resp, err := cli.client.RequestVisa(defaultCtx, apikey, srcTether.AsSlice(), int8(l3Type), pkt)
	if err != nil {
		n.zlog.Infow("request visa failed", "error", err)
		return nil, fmt.Errorf("request-visa failed: %w", err)
	}
	n.plog.Log(Rev, "visa_response")
	n.zlog.Infow("request visa succeeds", "visa_id", resp.Visa.IssuerID)
	return resp, nil
}

// Close anything that needs to be closed.  This prepares for a clean
// exit.
func (n *Node) Close() {
	if n.apiKey != "" {
		_ = n.disconnectActors()
		_ = n.DeRegister(n.apiKey)
		n.apiKey = ""
	}
	if n.vss != nil {
		n.vss.Close()
		n.vss = nil
	}
}

// Clear any transient state (for use in-between tests).
func (n *Node) Reset() {
	if n.apiKey != "" {
		_ = n.disconnectActors()
	}
	if n.vss != nil {
		n.vss.Reset()
	}
	n.SetPlogEnabled(true)
}

// The node keeps track of successful calls to AuthorizeConnect, this function will
// send matching calls to ActorDisconnect to clean up state held on the visa service side.
func (n *Node) disconnectActors() error {
	count := len(n.connects)
	if count == 0 {
		return nil
	}
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return err
	}
	defer cli.Close()
	var lastErr error
	err_count := 0
	for _, addr := range n.connects {
		n.plog.Log(Fwd, "actor_disconnect")
		n.zlog.Infow("node->vs: ACTOR_DISCONNECT", "zpr_addr", addr)
		err := cli.client.ActorDisconnect(defaultCtx, n.apiKey, addr.AsSlice())
		if err != nil {
			err_count++
			lastErr = err
			n.zlog.Infow("actor_disconnect failed", "error", err)
		}
	}
	n.connects = make([]netip.Addr, 0)
	if err_count == 0 {
		n.zlog.Infow("actor_disconnect succeeds", "total", count)
		return nil
	} else {
		n.zlog.Infow("actor_disconnect failed", "failures", err_count, "total", count)
		return lastErr
	}
}

func (n *Node) PopPolicyInfo() *vsapi.PolicyInfo {
	if n.vss == nil {
		return nil
	}
	select {
	case pi := <-n.vss.Policies:
		return pi
	default:
		return nil
	}
}

func (n *Node) PopVisa() *vsapi.VisaHop {
	if n.vss == nil {
		return nil
	}
	select {
	case vsa := <-n.vss.Visas:
		return vsa
	default:
		return nil
	}
}

func (n *Node) PopRevocation() *vsapi.VisaRevocation {
	if n.vss == nil {
		return nil
	}
	select {
	case vr := <-n.vss.Revokes:
		return vr
	default:
		return nil
	}
}

var defaultCtx = context.Background()

type TClient struct {
	transport thrift.TTransport
	client    *vsapi.VisaServiceClient
}

func newClient(addr netip.AddrPort) (*TClient, error) {
	cfg := &thrift.TConfiguration{
		ConnectTimeout: 5 * time.Second,
		SocketTimeout:  5 * time.Second,
	}

	protocolFac := thrift.NewTBinaryProtocolFactoryConf(nil)
	transportFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), cfg)

	var transport thrift.TTransport
	transport = thrift.NewTSocketConf(addr.String(), cfg)

	transport, err := transportFac.GetTransport(transport)
	if err != nil {
		return nil, fmt.Errorf("thrift GetTransport failed: %w", err)
	}
	// defer transport.Close()

	if err := transport.Open(); err != nil {
		return nil, fmt.Errorf("thrift transport.Open failed: %w", err)
	}

	iprot := protocolFac.GetProtocol(transport)
	oprot := protocolFac.GetProtocol(transport)

	return &TClient{
		transport: transport,
		client:    vsapi.NewVisaServiceClient(thrift.NewTStandardClient(iprot, oprot)),
	}, nil
}

func (c *TClient) Close() {
	c.transport.Close()
}

func (c *TClient) Hello() (*vsapi.HelloResponse, error) {
	return c.client.Hello(defaultCtx)
}

package mocks

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"zpr.org/vst/pkg/vsapi"

	"github.com/apache/thrift/lib/go/thrift"
	"go.uber.org/zap"
)

// Node is a mockup node for testing visa service.
type Node struct {
	zlog   *zap.SugaredLogger
	vsAddr netip.AddrPort
	apiKey string
}

func NewNode(vsAddr netip.AddrPort, lgr *zap.Logger) (*Node, error) {
	return &Node{
		zlog:   lgr.Sugar(),
		vsAddr: vsAddr,
	}, nil
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
	resp, err := cli.Hello()
	if err != nil {
		return nil, fmt.Errorf("hello failed: %w", err)
	}
	n.zlog.Infow("hello succeeds", "sid", resp.SessionID)
	return resp, nil
}

// If we get an API key, we keep it in our state.
func (n *Node) Authenticate(chalresp *vsapi.NodeAuthRequest) (string, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return "", err
	}
	defer cli.Close()
	n.zlog.Info("node->vs: AUTHENTICATE")
	apiKey, err := cli.client.Authenticate(defaultCtx, chalresp)
	if err != nil {
		n.zlog.Infow("authenticate failed", "error", err)
		return "", fmt.Errorf("authenticate failed: %w", err)
	} else {
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
	n.zlog.Infow("node->vs: AUTHORIZE CONNECT")
	resp, err := cli.client.AuthorizeConnect(defaultCtx, apikey, req)
	if err != nil {
		n.zlog.Infow("authorize connect failed", "error", err)
		return nil, fmt.Errorf("authorize-connect failed: %w", err)
	}
	n.zlog.Info("authorize connect succeeeds")
	return resp, nil
}

func (n *Node) RequestVisa(apikey string, srcTether netip.Addr, l3Type int, pkt []byte) (*vsapi.VisaResponse, error) {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return nil, err
	}
	n.zlog.Info("node->vs: REQUEST VISA")
	resp, err := cli.client.RequestVisa(defaultCtx, apikey, srcTether.AsSlice(), int8(l3Type), pkt)
	if err != nil {
		n.zlog.Infow("request visa failed", "error", err)
		return nil, fmt.Errorf("request-visa failed: %w", err)
	}
	n.zlog.Infow("request visa succeeds", "visa_id", resp.Visa.IssuerID)
	return resp, nil
}

// Close anything that needs to be closed.  This prepares for a clean
// exit.
func (n *Node) Close() {
	// TODO: disconnect from visa service
	// TODO: shutdown our own vss
	if n.apiKey != "" {
		_ = n.DeRegister(n.apiKey)
		n.apiKey = ""
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

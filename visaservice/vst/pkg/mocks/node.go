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
}

func NewNode(vsAddr netip.AddrPort, lgr *zap.Logger) (*Node, error) {
	return &Node{
		zlog:   lgr.Sugar(),
		vsAddr: vsAddr,
	}, nil
}

func (n *Node) ConnectToVisaService() error {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return err
	}
	defer cli.Close()
	resp, err := cli.Hello()
	if err != nil {
		return fmt.Errorf("hello failed: %w", err)
	}
	n.zlog.Infow("hello succeeds", "sid", resp.SessionID)
	return nil
}

func (n *Node) TestRepeatHello(reps int) error {
	cli, err := newClient(n.vsAddr)
	if err != nil {
		return err
	}
	defer cli.Close()

	sids := make(map[int32]bool)
	dupeCount := 0

	n.zlog.Infow("testing hello from node", "reps", reps)
	for i := 0; i < reps; i++ {
		resp, err := cli.Hello()
		if err != nil {
			return fmt.Errorf("hello failed at rep %d: %w", i, err)
		}
		if sids[resp.SessionID] {
			dupeCount++
		} else {
			sids[resp.SessionID] = true
		}
	}
	if dupeCount > 0 {
		n.zlog.Warnw("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	} else {
		n.zlog.Infow("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	}
	return nil
}

// Close anything that needs to be closed.  This prepares for a clean
// exit.
func (n *Node) Close() {
	// TODO: disconnect from visa service
	// TODO: shutdown our own vss
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

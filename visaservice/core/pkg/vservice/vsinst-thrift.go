package vservice

import (
	"context"
	"fmt"
	"net/netip"

	"zpr.org/vs/pkg/vsapi"

	"github.com/apache/thrift/lib/go/thrift"
)

func (vs *VSInst) startThriftBlocking(listenAddr netip.Addr, port uint16) error {

	var transport thrift.TServerTransport
	var err error

	transport, err = thrift.NewTServerSocket(fmt.Sprintf("%v:%d", listenAddr, port))
	if err != nil {
		return err
	}

	processor := vsapi.NewVisaServiceProcessor(vs)
	transportFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), nil)
	protocolFac := thrift.NewTBinaryProtocolFactoryConf(nil)

	server := thrift.NewTSimpleServer4(processor, transport, transportFac, protocolFac)

	vs.thriftServer = server
	return server.Serve()
}

func (vs *VSInst) Hello(ctx context.Context) (*vsapi.VSChallenge, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (vs *VSInst) Authenticate(ctx context.Context,
	challenge *vsapi.VSChallenge,
	timestamp int64,
	nodeCert []byte,
	hmac []byte,
	nodeAgent *vsapi.Agent) (vsapi.APIKey, error) {

	return "", fmt.Errorf("not implemented")
}

func (vs *VSInst) DeRegister(ctx context.Context, key vsapi.APIKey) error {
	return nil
}

func (vs *VSInst) AuthorizeConnect(ctx context.Context, key vsapi.APIKey, request *vsapi.ConnectRequest) (*vsapi.ConnectResponse, error) {
	return nil, fmt.Errorf("Not implemented")
}

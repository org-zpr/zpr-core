package vservice

import (
	"context"
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"
	"zpr.org/vs/pkg/vssapi"
)

type VSSCli struct{}

// `serviceAddr` is nodes vss service address in 'ADDR:PORT' form.
func (vc *VSSCli) SendNetworkPolicy(serviceAddr string, policyID uint64, configID uint64) error {

	protoFac := thrift.NewTBinaryProtocolFactoryConf(nil)
	transFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), nil)

	transport, err := transFac.GetTransport(thrift.NewTSocketConf(serviceAddr, nil))
	if err != nil {
		return fmt.Errorf("failed to get thrift transport: %v", err)
	}
	defer transport.Close()
	if err := transport.Open(); err != nil {
		return fmt.Errorf("failed to open transport: %v", err)
	}
	iprot := protoFac.GetProtocol(transport)
	oprot := protoFac.GetProtocol(transport)

	client := vssapi.NewVisaSupportClient(thrift.NewTStandardClient(iprot, oprot))

	pi := vssapi.PolicyInfo{
		PolicyID: int64(policyID),
		ConfigID: int64(configID),
	}

	return client.NetworkPolicyInstalled(context.Background(), &pi)
}

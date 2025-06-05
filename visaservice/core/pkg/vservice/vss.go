package vservice

import (
	"context"
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"
	"zpr.org/vsapi"
)

type VSSCli struct {
	serviceAddr string
}

func NewVSSCli(serviceAddr string) *VSSCli {
	return &VSSCli{
		serviceAddr: serviceAddr,
	}
}

type ThriftCallF func(*vsapi.VisaSupportClient) error

func (vc *VSSCli) withClient(f ThriftCallF) error {
	protoFac := thrift.NewTBinaryProtocolFactoryConf(nil)
	transFac := thrift.NewTFramedTransportFactoryConf(thrift.NewTTransportFactory(), nil)

	transport, err := transFac.GetTransport(thrift.NewTSocketConf(vc.serviceAddr, nil))
	if err != nil {
		return fmt.Errorf("failed to get thrift transport: %v", err)
	}

	defer transport.Close()

	if err := transport.Open(); err != nil {
		return fmt.Errorf("failed to open transport: %v", err)
	}
	iprot := protoFac.GetProtocol(transport)
	oprot := protoFac.GetProtocol(transport)

	client := vsapi.NewVisaSupportClient(thrift.NewTStandardClient(iprot, oprot))
	return f(client) // ensures transport is closed
}

// `serviceAddr` is nodes vss service address in 'ADDR:PORT' form.
func (vc *VSSCli) SendNetworkPolicy(policyID uint64, configID uint64) error {
	pi := vsapi.PolicyInfo{
		PolicyID: int64(policyID),
		ConfigID: int64(configID),
	}
	return vc.withClient(func(client *vsapi.VisaSupportClient) error {
		return client.NetworkPolicyInstalled(context.Background(), &pi)
	})
}

func (vc *VSSCli) SendRevocation(config_id int64, issuer_id uint32) error {
	rev := vsapi.VisaRevocation{
		IssuerID:      int32(issuer_id),
		Configuration: config_id,
	}
	return vc.withClient(func(client *vsapi.VisaSupportClient) error {
		return client.RevokeVisas(context.Background(), []*vsapi.VisaRevocation{&rev})
	})
}

func (vc *VSSCli) SendRevocations(revocations []*vsapi.VisaRevocation) error {
	return vc.withClient(func(client *vsapi.VisaSupportClient) error {
		return client.RevokeVisas(context.Background(), revocations)
	})
}

func (vc *VSSCli) SendVisa(issuerID uint32, v *vsapi.Visa, hopCount uint32) error {
	hoppity := vsapi.VisaHop{
		Visa:     v,
		HopCount: int32(hopCount),
		IssuerID: int32(issuerID),
	}
	return vc.withClient(func(client *vsapi.VisaSupportClient) error {
		return client.InstallVisas(context.Background(), []*vsapi.VisaHop{&hoppity})
	})
}

func (vc *VSSCli) SendVisas(visas []*vsapi.VisaHop) error {
	return vc.withClient(func(client *vsapi.VisaSupportClient) error {
		return client.InstallVisas(context.Background(), visas)
	})
}

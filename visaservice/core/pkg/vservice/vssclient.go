package vservice

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snio/vsio"
	"zpr.org/vs/pkg/snio/vss"
	"zpr.org/vs/pkg/vservice/auth"
)

const RPC_TIMEOUT = 2 * time.Second

type VSSClient struct {
	log      logr.Logger
	conn     *grpc.ClientConn
	c        vss.VisaServiceSupportClient
	nodeName string
	dummyCS  ConstraintService // PLACEHOLDER
	vsPubkey *rsa.PublicKey
	NodeAddr netip.Addr // node address set in constructor
}

func NewVSSClient(log logr.Logger, addr netip.Addr, port int, nodeName string, clientCreds credentials.TransportCredentials, agentSigningPublicKey *rsa.PublicKey) (*VSSClient, error) {
	if !addr.Is6() {
		return nil, errors.New("vss client only supports ipv6 addresses")
	}
	cli := &VSSClient{
		log:      log,
		nodeName: nodeName,
		dummyCS:  NewDummyConstraintService(),
		vsPubkey: agentSigningPublicKey,
		NodeAddr: addr,
	}
	addrPort := fmt.Sprintf("[%v]:%d", addr.String(), port)
	if err := cli.connect(addrPort, clientCreds); err != nil {
		return nil, fmt.Errorf("grpc connect to visa support service failed: %w", err)
	}
	return cli, nil
}

func (c *VSSClient) Disconnect() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.c = nil
	}
}

// TODO: What args needs to be sent here?
func (c *VSSClient) Hello() error {
	req := &vss.HelloRequest{}

	ctx, cancel := context.WithTimeout(context.Background(), RPC_TIMEOUT)
	defer cancel()

	resp, err := c.c.VisaServiceHello(ctx, req) // TODO: use a timeout
	if err != nil {
		return err
	}
	if resp.ChallengeType != "none" {
		return fmt.Errorf("expected no auth challenge, got %v", resp.ChallengeType)
	}
	return nil
}

func (c *VSSClient) AuthRequest(vsName string, token []byte) (*vss.AuthResponse, error) {
	req := &vss.AuthRequest{
		AccessToken: token,
		VsTlsName:   vsName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), RPC_TIMEOUT)
	defer cancel()

	resp, err := c.c.VisaServiceAuth(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Sets `conn` and `c` fields if connect is successful.
func (c *VSSClient) connect(addrPort string, creds credentials.TransportCredentials) error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithAuthority(c.nodeName),
	}
	conn, err := grpc.Dial(addrPort, opts...)
	if err != nil {
		return err
	}
	c.conn = conn
	c.c = vss.NewVisaServiceSupportClient(conn)
	return nil
}

func (c *VSSClient) InstallPolicy(bootstrap bool, format uint32, policyData []byte, configID uint64, vsVisas []*vsio.Visa) (*vss.InstallResponse, error) {
	var vbufs []*vss.VisaBuffer
	for _, v := range vsVisas {
		vbytes, err := proto.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal visa: %w", err)
		}
		vbufs = append(vbufs, &vss.VisaBuffer{VsData: vbytes})
	}
	req := &vss.InstallRequest{
		PayloadFormat: format,
		Payload:       policyData,
		ConfigId:      configID,
		Visas:         vbufs,
	}
	if bootstrap {
		req.InstallType = vss.InstallType_VSS_INSTALL_TYPE_BOOTSTRAP
	} else {
		req.InstallType = vss.InstallType_VSS_INSTALL_TYPE_POLICY
	}

	ctx, cancel := context.WithTimeout(context.Background(), RPC_TIMEOUT)
	defer cancel()
	resp, err := c.c.Install(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// "directory service" interface -- uses the support service to lookup entries in RAFT on the node.
//
// The visa service inserts agent entries into the system via the AuthorizeConnect call.
// The visa service signs those agents so we check to see if our signature is on them
// when we get them back.
func (c *VSSClient) AgentAtContactAddr(address netip.Addr) (*vsio.Agent, error) {
	c.log.Info("requesting lookup agent at contact address", "address", address)
	req := &vss.LookupAgentRequest{
		Key:     vss.LookupAgentKey_LOOKUP_KEY_CONTACT_ADDR,
		Address: address.AsSlice(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), RPC_TIMEOUT)
	defer cancel()
	resp, err := c.c.LookupAgent(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Agent == nil {
		return nil, nil
	}
	if err := verifySignatureOverVsioAgent(resp.Agent, SigningKeyID, c.vsPubkey); err != nil {
		c.log.WithError(err).Info("(lookup) returned agent fails siguature verification", "query_addr", address)
	}
	return resp.Agent, nil
}

// TODO: Put the constraint service into the protocol buffer file for support service and then implement here.
func (c *VSSClient) ProposeConstraint(cons *RConstraint) {
	c.log.Info("(TODO) propose constraint", "key", cons.Key)
	c.dummyCS.ProposeConstraint(cons)
}

// TODO: Put the constraint service into the protocol buffer file for support service and then implement here.
func (c *VSSClient) ConstraintByKey(key string) *RConstraint {
	c.log.Info("(TODO) constraint by key", "key", key)
	return c.dummyCS.ConstraintByKey(key)
}

// TODO: Add revocation support to VSS protocol.

func (c *VSSClient) ProposeClearAllRevokes(_ string)               {}
func (c *VSSClient) ListRevocationKeysFor(_ string) []string       { return nil }
func (C *VSSClient) GetRevoke(_ string) *auth.Revoke               { return nil }
func (C *VSSClient) ProposeRevokeCredential(pver, cred string)     {}
func (C *VSSClient) ProposeRevokeAuthority(pver, credIdent string) {}

package vservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"zpr.org/vs/pkg/agent"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/snio/vsio"

	"zpr.org/vsx/polio"
)

func (vs *VSInst) startGrpc(listenAddr netip.Addr, port int) error {
	vs.SetLocalAddr(listenAddr)
	var conStr string
	if listenAddr.Is6() {
		conStr = fmt.Sprintf("[%v]:%d", listenAddr.String(), port)
	} else {
		conStr = fmt.Sprintf("%v:%d", listenAddr.String(), port)
	}
	lis, err := net.Listen("tcp", conStr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	opts := []grpc.ServerOption{
		grpc.Creds(vs.grpcCreds),
	}
	vs.grpcSvc = grpc.NewServer(opts...)
	vsio.RegisterVisaServiceServer(vs.grpcSvc, vs)

	rlExitC := make(chan struct{})
	defer close(rlExitC)
	go vs.runloop(rlExitC)

	vs.log.Infof("visa service node %d starts on %v", vs.nodeNumber, conStr)
	if err = vs.grpcSvc.Serve(lis); err != nil {
		vs.log.Errorf("visa service exited with error: %v", err)
		return err
	}
	vs.trySignal(&sig{VSSignalExit})
	vs.log.Info("visa service grpc exiting")
	return nil
}

// StopGrpc stops the server, blocking until complete.
func (vs *VSInst) stopGrpc() {
	if vs.grpcSvc != nil {
		vs.grpcSvc.Stop()
		vs.grpcWg.Wait()
	}
}

func (vs *VSInst) checkAccess(addr netip.Addr) bool {
	// This is called with the peer address. Under unit-testing this will not work correctly since peer address is undefined.
	return vs.HasRegisteredNode(addr) || vs.allowInvalidPeerAddr
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

// --------------------------------- GRPC BEGIN ----------------------------- //

func (vs *VSInst) Register(ctx context.Context, req *vsio.VSRegisterRequest) (*vsio.VSRegisterResponse, error) {
	peer := peerAddrFromCtx(ctx)
	naddr, addrOK := netip.AddrFromSlice(req.GetNodeAddr())
	vs.log.Info("register", "peer", peer, "node_addr", naddr)
	if !addrOK && !vs.allowInvalidPeerAddr {
		return nil, status.Errorf(codes.InvalidArgument, "invalid node address")
	}
	if (naddr != peer || !peer.IsValid()) && !vs.allowInvalidPeerAddr {
		vs.log.Info("register failed: node address is not peer address")
		return nil, status.Errorf(codes.InvalidArgument, "invalid node address")
	}
	vs.AddNode(naddr)
	vs.registeredNodes.Lock()
	defer vs.registeredNodes.Unlock()
	vs.registeredNodes.table[naddr] = &PeerRecord{
		RegistrationTime: time.Now(),
	}
	return &vsio.VSRegisterResponse{
		Success: true,
	}, nil
}

func (vs *VSInst) DeRegister(ctx context.Context, req *vsio.VSDeRegisterRequest) (*vsio.VSDeRegisterResponse, error) {
	peer := peerAddrFromCtx(ctx)
	naddr, addrOk := netip.AddrFromSlice(req.GetNodeAddr())
	vs.log.Info("de-register", "peer", peer, "node_addr", naddr)
	if (addrOk && (peer == naddr)) || vs.allowInvalidPeerAddr {
		vs.registeredNodes.Lock()
		defer vs.registeredNodes.Unlock()
		delete(vs.registeredNodes.table, naddr)
	}
	vs.RemoveNode(naddr)
	return &vsio.VSDeRegisterResponse{
		Success: addrOk,
	}, nil
}

func (vs *VSInst) AuthorizeConnect(ctx context.Context, req *vsio.VSConnectRequest) (*vsio.VSConnectResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("authorize connect", "peer", peer, "at_dock", net.IP(req.DockAddr).String(), "req_addr", net.IP(req.ReqAddr).String())
	if !vs.checkAccess(peer) {
		vs.log.Info("authorize connect failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}
	var nodeAgent *agent.Agent
	if req.Token != nil && bytes.Equal(req.Token, vs.accessToken) {
		nodeAgent = agent.NewAgentFromSnioAgent(req.NodeAgent)
	}
	vs.registeredNodes.Lock()
	if rr, found := vs.registeredNodes.table[peer]; found {
		rr.ConnectRequestsCount++
	}
	vs.registeredNodes.Unlock()
	resp, err := vs.ApproveConnection(req, nodeAgent)
	if err != nil {
		resp = &vsio.VSConnectResponse{
			ConId:    req.GetConId(),
			Success:  false,
			ErrorMsg: err.Error(),
		}
		vs.log.Info("authorize connect fails", "peer", peer, "error", err)
	} else {
		resp.Success = true
		vs.log.Info("authorize connect succeeds", "peer", peer, "agent_ident", resp.Agent.Ident, "config_id", resp.Agent.ConfigId)
	}
	return resp, nil
}

func (vs *VSInst) RequestVisa(ctx context.Context, req *vsio.VSRequest) (*vsio.VSResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("request visa", "peer", peer)
	if !vs.checkAccess(peer) {
		vs.log.Info("request visa failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}
	vs.registeredNodes.Lock()
	if rr, found := vs.registeredNodes.table[peer]; found {
		rr.VisaRequestsCount++
	}
	vs.registeredNodes.Unlock()
	pp := vs.getPolicy() // take & release lock
	pver := uint64(0)
	if pp != nil {
		pver = pp.VersionNumber()
	}
	tetherAddr, ok := netip.AddrFromSlice(req.GetSrcTetherAddr())
	if !ok {
		return &vsio.VSResponse{
			Success:  false,
			ErrorMsg: "invalid tether address",
		}, errors.New("invalid tether address on visa request")
	}
	resp, err := vs.doRequestVisa(ctx, tetherAddr, snioPacketDescToIpTraffic(req.GetTraffic()), 0, pver)
	if err != nil {
		resp = &vsio.VSResponse{
			Success:  false,
			ErrorMsg: err.Error(),
		}
	}
	return resp, nil
}

func (vs *VSInst) SubmitStats(ctx context.Context, req *vsio.VSStatsRequest) (*vsio.VSStatsResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("submit stats", "peer", peer)
	if !vs.checkAccess(peer) {
		vs.log.Info("submit stats failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}

	vs.reportVisaStats(req.GetIssuerId(), req.GetCapKey(), req.GetBytesUsed())
	return &vsio.VSStatsResponse{}, nil
}

func (vs *VSInst) Poll(ctx context.Context, req *vsio.VSPollRequest) (*vsio.VSPollResponse, error) {
	peer := peerAddrFromCtx(ctx)

	// Polling is very frequent so is annoying to log. Instead we log the first one.
	// TODO: maybe a housekeeping thread to log our stats from connected nodes and flag nodes we haven't heard from in a while.
	vs.registeredNodes.Lock()
	if rr, found := vs.registeredNodes.table[peer]; found {
		if rr.LastPollTime.IsZero() {
			vs.log.Info("first poll", "peer", peer)
		}
		rr.LastPollTime = time.Now()
	} else {
		// hmm not found?
		vs.log.Info("poll from unregistered", "peer", peer)
	}
	vs.registeredNodes.Unlock()

	if !vs.checkAccess(peer) {
		vs.log.Info("poll failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}

	// TODO: Do not trust the caller to set the dock address correctly, instead
	//       use the peer info built in to GRPC.
	mbox := net.IP(req.DockAddr).String()
	resp := &vsio.VSPollResponse{}
	const qcount = 100
	msgs, ok := vs.mb.MessagesFor(mbox, qcount)
	if !ok {
		// This is an error - node should inform us of new nodes.
		vs.log.Info("poll request from unknown node, ignoring", "addr", mbox, "peer", peer)
		return resp, nil
	}
	for _, m := range msgs {
		if len(m.Revokes) > 0 {
			resp.Revokes = append(resp.Revokes, m.Revokes...)
		}
		if len(m.Visas) > 0 {
			resp.Visas = append(resp.Visas, m.Visas...)
		}
	}
	resp.More = len(msgs) == qcount // guessing...
	return resp, nil
}

// GetTopology returns any links from policy for which the requestor node address (ZIN) is either a
// source or destination.
//
// The links returned are always set up so the source is the requestor.
func (vs *VSInst) GetTopology(ctx context.Context, req *vsio.VSTopoRequest) (*vsio.VSTopoResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("get topology", "peer", peer)
	if !vs.checkAccess(peer) {
		vs.log.Info("get topology failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}

	// TODO: Do not trust the caller to set the dock address correctly, instead
	//       use the peer info built in to GRPC.
	nodeAddr := net.IP(req.GetNodeAddr())
	p, _, _ := vs.getPolicyMatcherConfig()
	pver := p.VersionNumber()

	if (req.PolicyVersion > 0) && (req.PolicyVersion != pver) {
		return nil, status.Errorf(codes.InvalidArgument, "wrong policy version")
	}

	// When we are source, the terms include the contact details (eg, hostname on public IP network).
	// When we are a term, the source is present only by ZIN. Therefore we need to do more work
	// to determin the public IP contact details in that case.

	// Here we build up a list of the overlay network addresses for all terms.
	nodeAddrs := make(map[string]*vsio.VSTopoResponse_NodeAddr)
	for _, lnk := range p.ListLinks() {
		for _, trm := range lnk.GetTerms() {
			nodeAddrs[net.IP(trm.ZprId).String()] = &vsio.VSTopoResponse_NodeAddr{
				ZprId:   trm.ZprId,
				Host:    trm.Host,
				Port:    trm.Port,
				ExtAuth: trm.ExtAuth, // TODO: needed here?
				Key:     trm.Key,
			}
		}
	}

	// Keep track of all terms added to for the requesting node
	terms := make(map[string]bool)

	// Basically we will return a link struct where the requestor is the source
	// and all relevant links are terms.
	resp := &vsio.VSTopoResponse{
		PolicyVersion: pver,
	}
	respLink := vsio.VSTopoResponse_Link{
		SourceId: nodeAddr, // requestor
	}

	for _, lnk := range p.ListLinks() {
		lsrc := net.IP(lnk.GetSourceId())
		if lsrc.Equal(nodeAddr) { // We are a source here. So we can copy this directly to reply.
			for _, trm := range lnk.GetTerms() {
				// Only add term if not already there.
				tKey := net.IP(trm.ZprId).String()
				if !terms[tKey] {
					respLink.Terms = append(respLink.Terms, &vsio.VSTopoResponse_NodeAddr{
						ZprId:   trm.ZprId,
						Host:    trm.Host,
						Port:    trm.Port,
						ExtAuth: trm.ExtAuth, // TODO: needed here?
						Key:     trm.Key,
					})
					terms[tKey] = true
				}
			}
		} else { // We are not source. Check if we are a term.
			for _, trm := range lnk.GetTerms() {
				taddr := net.IP(trm.GetZprId())
				if taddr.Equal(nodeAddr) {
					// We are a term, so we need to link back to the source. We better know the source
					// network contact details.
					lsrc := net.IP(lnk.SourceId).String()
					if contact, ok := nodeAddrs[lsrc]; !ok {
						vs.log.Warn("topo link required but IP target address unknown", "destNode", lsrc)
					} else if !terms[lsrc] {
						// Add the source of this link as a term for us -- if it is not there already.
						respLink.Terms = append(respLink.Terms, contact)
						terms[lsrc] = true
					}
					break // done with this source
				}
			}
		}
	}

	if len(respLink.Terms) > 0 {
		resp.Links = append(resp.Links, &respLink)
	}
	return resp, nil
}

func (vs *VSInst) HostAdded(ctx context.Context, req *vsio.VSHostAddRequest) (*vsio.VSHostAddResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("host_added", "peer", peer)
	if !vs.checkAccess(peer) {
		vs.log.Info("host_added request failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}
	if err := verifySignatureOverVsioAgent(req.Agent, SigningKeyID, &vs.agentSigningKey.PublicKey); err != nil {
		vs.log.WithError(err).Info("(host-added) passed agent fails siguature verification")
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent signature")
	}
	pp, _, curConfig := vs.getPolicyMatcherConfig()
	if curConfig != req.Configuration {
		vs.log.Info("host-add with different configuration", "current", curConfig, "on_reqest", req.Configuration)
	}
	errCount := 0
	for _, serviceName := range req.Agent.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				if svcAddr, ok := netip.AddrFromSlice(req.Agent.GetAuthAddr()); ok {
					err := vs.authr.AddDatasourceProvider(serviceName, svcAddr, req.Configuration)
					if err != nil {
						vs.log.WithError(err).Error("failed to add auth service", "service_name", serviceName)
						errCount++
					} else {
						vs.log.Info("service added", "service", serviceName, "address", svcAddr)
					}
				}
			}
		}
	}
	// Our API here isn't very flexible for reporting errors. Not really clear with the
	// sending node could do about it anyway.
	if errCount > 0 {
		return nil, status.Errorf(codes.Internal, "failed to add %d auth services", errCount)
	}
	return &vsio.VSHostAddResponse{}, nil
}

func (vs *VSInst) HostRemoved(ctx context.Context, req *vsio.VSHostRemoveRequest) (*vsio.VSHostRemoveResponse, error) {
	peer := peerAddrFromCtx(ctx)
	vs.log.Info("host_removed", "peer", peer)
	if !vs.checkAccess(peer) {
		vs.log.Info("host_removed request failed: VS access denied")
		return nil, status.Errorf(codes.PermissionDenied, "access denied")
	}
	if err := verifySignatureOverVsioAgent(req.Agent, SigningKeyID, &vs.agentSigningKey.PublicKey); err != nil {
		vs.log.WithError(err).Info("(host-added) passed agent fails siguature verification")
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent signature")
	}
	pp, _, curConfig := vs.getPolicyMatcherConfig()
	if curConfig != req.Configuration {
		vs.log.Info("host-remove with different configuration", "current", curConfig, "on_request", req.Configuration)
	}
	for _, serviceName := range req.Agent.GetProvides() {
		if psvc := pp.ServiceByName(serviceName); psvc != nil {
			if psvc.Type == polio.SvcT_SVCT_AUTH {
				if vs.authr.RemoveServiceByPrefix(psvc.GetPrefix()) > 0 {
					vs.log.Info("host_removed", "lost_service", serviceName)
				}
			}
		}
	}

	return &vsio.VSHostRemoveResponse{}, nil
}

// --------------------------------- GRPC END ------------------------------- //

func snioPacketDescToIpTraffic(pd *vsio.PacketDesc) *snip.Traffic {
	tcpflags := uint16(pd.GetFlags())
	syn := (tcpflags & 0x0002) > 0
	ack := (tcpflags & 0x0010) > 0

	saddr, _ := netip.AddrFromSlice(pd.GetSource())
	daddr, _ := netip.AddrFromSlice(pd.GetDest())

	var icmpa netip.Addr
	if ica := pd.GetIcmpAddr(); ica != nil {
		icmpa, _ = netip.AddrFromSlice(ica)
	}
	return &snip.Traffic{
		SrcAddr:           saddr,
		DstAddr:           daddr,
		Proto:             snip.Protocol(pd.GetProtocol()),
		SrcPort:           uint16(pd.GetSrcPort()),
		DstPort:           uint16(pd.GetDstPort()),
		Connect:           syn && !ack,
		Syn:               syn,
		Fin:               (tcpflags & 0x0001) > 0,
		Rst:               (tcpflags & 0x0004) > 0,
		Urg:               (tcpflags & 0x0020) > 0,
		Psh:               (tcpflags & 0x0008) > 0,
		Ack:               ack,
		ICMPType:          byte(pd.GetIcmpType()),
		ICMPCode:          byte(pd.GetIcmpType()),
		ICMPTargetAddress: icmpa,
		Size:              int(pd.GetSize()),
		Flags:             pd.GetFlags(),
	}
}

package libvisa

import (
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"
	"google.golang.org/protobuf/proto"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vsx/snio/vsio"
)

func VsioVisaToThrift(pb_visa *vsio.Visa) *vsapi.Visa {
	vv := new(vsapi.Visa)
	vv.IssuerID = int32(pb_visa.IssuerId)
	vv.Configuration = int64(pb_visa.Configuration)
	vv.Expires = pb_visa.Expires
	vv.Source = pb_visa.Source
	vv.Dest = pb_visa.Dest
	vv.SourceContact = pb_visa.SourceContact
	vv.DestContact = pb_visa.DestContact
	switch pb_visa.DockPep {
	case PEPDockTCP:
		vv.DockPep = vsapi.PEPIndex_TCP
		var pargs vsio.PEPArgsTCP
		if err := proto.Unmarshal(pb_visa.GetDockPepArgs(), &pargs); err != nil {
			panic("failed to unmarshal dock pep args")
		}
		vsapiArgs := &vsapi.PEPArgsTCPUDP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			SourcePort:        int32(pargs.SourcePort),
			DestPort:          int32(pargs.DestPort),
			Server:            pargs.Server,
			IcmpAllowed:       make([]int32, len(pargs.IcmpAllowed)),
		}
		for i, v := range pargs.IcmpAllowed {
			vsapiArgs.IcmpAllowed[i] = int32(v)
		}
		vv.TcpudpPepArgs_ = vsapiArgs
	case PEPDockUDP:
		vv.DockPep = vsapi.PEPIndex_UDP
		var pargs vsio.PEPArgsUDP
		if err := proto.Unmarshal(pb_visa.GetDockPepArgs(), &pargs); err != nil {
			panic("failed to unmarshal dock pep args")
		}
		vsapiArgs := &vsapi.PEPArgsTCPUDP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			SourcePort:        int32(pargs.SourcePort),
			DestPort:          int32(pargs.DestPort),
			Server:            pargs.DestPortMode == 0,
			IcmpAllowed:       make([]int32, len(pargs.IcmpAllowed)),
		}
		for i, v := range pargs.IcmpAllowed {
			vsapiArgs.IcmpAllowed[i] = int32(v)
		}
		vv.TcpudpPepArgs_ = vsapiArgs
	case PEPDockICMP:
		vv.DockPep = vsapi.PEPIndex_ICMP
		var pargs vsio.PEPArgsICMP
		if err := proto.Unmarshal(pb_visa.GetDockPepArgs(), &pargs); err != nil {
			panic("failed to unmarshal dock pep args")
		}
		vsapiArgs := &vsapi.PEPArgsICMP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			IcmpTypeCode:      int32(pargs.IcmpTypeCode),
			IcmpAntecedent:    int32(pargs.IcmpAntecedent),
			StateTimeoutMs:    thrift.Int32Ptr(int32(pargs.StateTimeoutMs)),
			OneShot:           pargs.OneShot,
		}
		vv.IcmpPepArgs_ = vsapiArgs
	default:
		panic(fmt.Sprintf("unknown dock pep: %v", pb_visa.DockPep))
	}
	vv.SessionKey = &vsapi.KeySet{
		Format:     int32(pb_visa.SessionKey.Format),
		IngressKey: pb_visa.SessionKey.IngressKey,
		EgressKey:  pb_visa.SessionKey.EgressKey,
	}
	vv.Cons = &vsapi.Constraints{
		Bw:                  pb_visa.Cons.Bw,
		BwLimitBps:          int64(pb_visa.Cons.BwLimitBps),
		DataCapID:           pb_visa.Cons.DataCapId,
		DataCapBytes:        int64(pb_visa.Cons.DataCapBytes),
		DataCapAffinityAddr: pb_visa.Cons.DataCapAffinity,
	}
	if pb_visa.Sig != nil {
		vv.Sig = &vsapi.Signature{
			Type:      int32(pb_visa.Sig.Type),
			Signature: pb_visa.Sig.Signature,
		}
	}
	return vv
}

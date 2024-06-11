package vsio

import "net/netip"

func (cr *VSConnectRequest) HasReqAddr() bool {
	return cr.ReqAddr != nil
}

func (cr *VSConnectRequest) ParseReqAddr() (netip.Addr, bool) {
	return netip.AddrFromSlice(cr.ReqAddr)
}

func (cr *VSConnectRequest) ParseDockAddr() (netip.Addr, bool) {
	return netip.AddrFromSlice(cr.DockAddr)
}

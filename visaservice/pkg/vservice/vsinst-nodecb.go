package vservice

import "net/netip"

// vsinst-nodecb - placeholder for code that looks like it needs the node to call in to in.
//                 So this is new API needs for the visa-service, I think.
//                 But can any node call these?  Maybe ok.
//                 The visa-service should keep track of the node it originally connected to and only permit that to call some of the functions.

// AddNode inform the visa service that a node has joined the ZPR. The node is then added
// to the list of expected "pollers" for visa service push messages.
//
// For now using the "register" call for this.
func (vs *VSInst) AddNode(addr netip.Addr) {
	// minor race condition here:
	id := addr.String()
	if !vs.mb.HasPoller(id) {
		vs.mb.AddPoller(id)
	}
}

// RemoveNode removes the node at address 'addr' from the pollers list.
func (vs *VSInst) RemoveNode(addr netip.Addr) {
	vs.mb.RemovePoller(addr.String())
}

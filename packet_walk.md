# Packet Walk

## Introduction

This document is intended to follow the lifetime of packets as they flow through the ZPR network and lay out noteworthy decision points along the way.  It is based on the content of the ZPR RFCs and intended as an implementation guide.

The walk is presented chronologically over the lifetime of a flow and is mainly for exploring expected cases.  This document will not exhaustively cover error cases.

For the purposes of this document specifically, an IP substrate is assumed, but fragmentation is ignored.  A later version may tackle fragmentation in more depth.

## A Packet Arrives

An agent initiates a flow by sending a packet to the Ingress Client Adapter, the gateway into the ZPR network.  At this point, the Adapter has no entry for the flow in its Agent Lookup Table (keyed by the 5-tuple) and the failure of that lookup will indicate that it needs to issue a ZDP Bind Request to the dock.  A Bind Request is created which includes the packet body and it is forwarded to the Dock.

If the packet is too big to include in the Bind Request, it is instead cached and as much of it as can fit is included in the Bind Request.

### Dock Receives A Bind Request

When the Dock receives the Bind Request it checks its visas to see if one of those matches the request it just received.  If it already has a matching visa, it allocates a new Tether ID for this flow and responds with a Bind Response.  The Bind Response tells the Adapter how to compress packets for this Tether.

If the dock does not have a visa, it issues a Visa Request to the visa service, packet included.  If the Adapter has sent too many Bind Requests, they may be rate-limited instead.

### Visa Service Receives A Visa Request

The Visa Service fully classifies the packet and checks it against policy.  If it finds matching policy, it responds with a visa.  The triggering packet is included only if it is a full packet and not truncated.

The Visa Service also sends the visa (sans packet) to each Node along the route.

If no matching visa is found, a negative visa is issued instead, only sent to the requesting Dock.

### Dock Receives A Visa Response

The Dock, upon receiving the Visa Response, will install the visa in its Dock Forwarding Table.  It will also allocate a Tether ID and send a Bind Response to the Adapter.  A Visa Herald message will be sent to the next Node.  This message will include the full packet if it was included in the Visa Response.

### Ingress Adapter Receives A Bind Response

The Adapter's outstanding Bind Request finally gets a response.  If the response indicates success, the Adapter will map the 5-tuple of the packet to the Tether ID registered in the Bind Response in its Agent Lookup Table.  If the full packet had been too large to forward to the Dock in the Bind Request, the cached packet is now forwarded to the Dock, using the compression specified in the Bind Response.

Any packets that were received on the stream between the issuance of the Bind Request and receiving the Response have been dropped.

### Egress Adapter Receives a Bind Request

When the heralding process reaches the last Node in the path, a Bind Request is issued to the Egress Adapter, containing all the information needed to uncompress packets on this stream and requesting a Stream ID.  The Adapter installs this information into its Dock Lookup Table.  As with previous hops, the resulting Stream ID is installed in the Node's forwarding table.

## A Packet Arrives And Matches A Flow

When the next packet arrives from the same agent, it now has an entry in the Agent Lookup Table to match.  A2A HMAC is calculated over the packet and appended to it.  The Adapter will compress the packet according to the rules established during the Bind exchange, placing a ZDP transit header in the compressed space.  That packet will then be forwarded on to the Dock.

The Dock should now also have an entry in its own Dock Forwarding Table, which is indexed by the Tether ID in the ZDP header.  It verifies that the packet received matches the visa that authorizes the flow.  If the verification fails, the packet is counted and dropped.  If the verification succeeds, the packet is forwarded on using the Link ID and Stream/Tether ID indicated by the Dock Forwarding Table.

If the next ZPR hop is another Node, it does the same, except that it does not need to re-verify the packet.  If, at any point, one of the Nodes does not recognize the Stream ID, the packet is dropped.

### Packet Reaches The Egress Adapter

When the packet arrives at its last ZPR hop, the Egress Client Adapter, it is uncompressed according to the rules installed during the Bind exchange.  After that, its A2A HMAC is checked for packet integrity.  Should the integrity check fail, the packet will be dropped.  Should it succeed, the packet is forwarded on to the Agent.  A reverse packet should flow seamlessly through all of the same stages and checks as this non-first forward packet.

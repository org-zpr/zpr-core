# Packet Walk

## Introduction

This document is intended to follow the lifetime of packets as they flow through the ZPR network and lay out noteworthy decision points along the way.  It is based on the content of the ZPR RFCs and intended as an implementation guide.

The walk is presented chronologically over the lifetime of a flow and is mainly for exploring expected cases.  This document will not exhaustively cover error cases.

For the purposes of this document specifically, an IP substrate is assumed, but fragmentation is ignored.  A later version may tackle fragmentation in more depth.

## A Packet Arrives

An agent initiates a flow by sending a packet to the Ingress Client Adapter, the gateway into the ZPR network.  At this point, the Adapter has no entry for the flow in its Agent Lookup Table (keyed by the 5-tuple) and the failure of that lookup will indicate that it needs to issue a ZDP Bind Request to the dock.  The Bind Request will be inserted into the packet and the packet will be forwarded to the dock.

If the packet is too big to attach the Bind Request to, it is instead cached and as much of it as can fit is copied onto a new ZDP Bind Request packet.

### Dock Receives A Bind Request

When the Dock receives the bind request it checks its visas to see if one of those captures the request it just received.  If it already has a matching visa, it allocates a new Stream ID for this flow and responds with a Bind Response.

If the dock does not have a visa, it issues a Visa Request to the visa service, packet included.  If the Adapter has sent too many Bind Requests, they may be rate-limited instead.

### Visa Service Receives A Visa Request

The Visa Service fully classifies the packet and checks for a matching visa.  If it finds one, it responds with the visa, again piggy-backed on the triggering packet.

The Visa Service also sends the visa (sans packet) to each Node along the route.

If no matching visa is found, a negative visa is issued instead, only sent to the requesting Dock.

### Dock Receives A Visa Response

The Dock, upon receiving the visa response, will install the visa in its local table.  It will also allocate a Stream ID and send a Bind Reponse to the Adapter.  If the full packet was included in the Visa Response, it will be forwarded on with a Visa Herald message to the next Node.

### Ingress Adapter Receives A Bind Response

The Adapter's outstanding Bind Request finally gets a response.  If the response is successful, the Adapter will map the 5-tuple of the packet to the Stream ID registered in the Bind Response in its Agent Lookup Table.  If the full packet had been too large to forward to the Dock in the Bind Request, the cached packet is now forwarded to the Dock.

### Egress Adapter Receives a Bind Request

When the heralding process reaches the last Node in the path, a Bind Request is issued to the Egress Adapter, containing all the information needed to uncompress packets on this stream and requesting a Stream ID.  The Adapter installs this information into its Dock Lookup Table.  As with previous hops, the resulting Stream ID is installed in the Node's forwarding table.

## A Packet Arrives And Matches A Flow

When the next packet arrives from the same agent, it now has an entry in the Agent Lookup Table to match.  HMAC is calculated over the packet and appended to it.  The Adapter will compress the packet according to the rules established during the Bind exchange, placing a ZDP transit header in the compressed space.  That packet will then be forwarded on to the Dock.

The Dock should now also have an entry in its own Forwarding Table, which is indexed by the Stream ID in the ZDP header.  It verifies that the packet received matches the visa that authorizes the flow.  If the verification fails, the packet is counted and dropped.  If the verification succeeds, the packet is forwarded on.

If the next ZPR hop is another Node, it does the same, except that it does not need to re-verify the packet.  If, at any point, one of the Nodes does not recognize the Stream ID, but has a visa for it, that is likely the result of a network failover event.  If the Node has neither an entry in its Forwarding Table nor a visa matching the traffic, it is likely that the visa has been revoked and the packet will be dropped.

### Packet Reaches The Egress Adapter

When the packet arrives at its last ZPR hop, the Egress Client Adapter, it is uncompressed according to the rules installed during the Bind exchange.  After that, its HMAC is checked for packet integrity.  Should the integrity check fail, the packet will be dropped.  Should it succeed, the packet is forwarded on to the Agent.  A reverse packet should flow seamlessly through all of the same stages and checks as this non-first forward packet.

# MILESTONE 4

Demonstrate bootstrap and BAS.

1. start a node
2. start VS using the m4-bas-color policy
3. start vs-adapter
4. start bas service (uses default ports 3999,4000)
5. start bas-adapter

Now the VS should know about the BAS authentication service.

Now start the cli-adapter.
- At this point adapter should be able to PING the BAS thanks to the
  user.color=red attribute.


Can we incorporate the DOCKER set up for this demo?  Maybe we
configure a setup with a node, a vs and a bas.  Then we can 
connect a service into that, and then the client into that too.


## addressing improvements

An adapter no longer is required to have a preconfigured ZPR address.
It should be best practice to just start an adapter and let the ZPR
network assign an address.  In that case do not manually create a tun
interface and do not set the zpr_addr in the config.

For the demo, only the node and vs need static addresses.






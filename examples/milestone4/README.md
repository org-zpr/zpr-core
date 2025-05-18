# MILESTONE 4

Demonstrate bootstrap and BAS.

1. start a node
2. start VS using the m4-bas-color policy
3. start vs-adapter
4. start bas service (uses default ports 3999,4000)
5. start bas-adapter

Now the VS should know about the BAS authentication service.

(TODO: Ideally everybody re-auths with it)

Now start the cli-adapter.
- Node should send a init-auth???
- Can we manually try to RSA auth with BAS?
- Not quite sure what should happen here (need to see the diagram)

- But somehow the adapter needs to run the RSA auth with BAS which
  returns a BLOB to adapter, which sends that BLOB to the node,
  which sends that BLOB to the visa service, 
  which then sends an OAUTH token-request to the BAS
  which then returns a JWT to the visa service that includes our
  "user.color" attribute.
  Visa service then accepts the auth.
  Node sends the ZPR-ADDR message to the adapter.

- At this point adapter should be able to PING the BAS thanks to the
  user.color=red attribute.





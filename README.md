# zpr-core
Core ZPR components

## Milestone 2 Startup Sequence

Here is the general "startup" sequence for milestone 2.

 * NODE - the only node
 * V/S ADAPTER - the adapter in front of the visa service.
 * VISASVC - the visa service
 * ADAPTER - one of the "regular" (non-visa service) adapters.


```
ADAPTER                 NODE                VISASVC
=======                ======               =======
  .                       |                    |
  .                       |                    |
  .     V/S ADAPTER       |                    |
  .     ===========       |                    |
  .         | kmh1        |                    |       =\
  .         +------------>|                    |        | security 
  .         |        kmh2 |---+                |        | association
  .         |<------------+   | node detect    |        |
  .         |             |   | VS CN          |       =/
  .         |hello(4)     |   |                |
  .         +------------>|   |                |
  .         |      hellor |   |                |
  .         |<------------+   |                |
  .         |             |   |                |
  .         | raa         |   |                |
  .         +------------>|   |                |       =\
  .         |        raar |   |                |        | ZPR address reg
  .         |<------------+   |                |       =/
  .         .             |<--+                |
  .         .             |                    |
  |                       | vs.hello           |       =\
  |                       +------------------->|        |
  |                       |      vs.hello-resp |        | node establishes    
  |                       |<-------------------+        | connection to 
  |                       |                    |        | visa service
  |                       | vs.authenticate    |        |
  |                       +------------------->|        |
  |                       |        vs.response |        |
  |                       |<-------------------+        |
  .                       .                    .       =/
  .                       .                    .
  |                       |                    |
  |  kmh1                 |                    |       =\ 
  +---------------------->|                    |        | security 
  |                  kmh2 |                    |        | association
  |<----------------------+                    |       =/
  |                       |                    |
  | hello                 |                    |
  +---------------------->|                    |
  |                hellor |                    |
  |<----------------------+                    |
  |                       |                    |  
  | raa(3)                |                    |
  +---------------------->|                    |       =\
  |                  raar |                    |        | ZPR address reg
  |<----------------------+                    |       =/
  |                       |                    |
  |                       | vs.auth_connect(1) |       =\
  |                       +------------------->|        | node tell
  |                       |      vs.auth_reply |        | visa service
  |                       |<-------------------+       =/
  |                       |                    |
  | echo(2)               |                    |       =\
  +---------------------->|                    |        | keep alive
  |             echo-resp |                    |        | connect check
  |<----------------------+                    |       =/
  |                       |                    |
  .                       .                    .
  . (traffic)             .                    .       =\
  +---------------------->| vs.visa-req        |        | visa 
  |                       +------------------->|        | request
  |                       |       vs.visa-resp |        |
  |                       |<-------------------+       =/
  |                       |                    |
  .                       .                    .
  .                       .                    .
  | terminate             |                    |       =\
  +---------------------->| vs.agent_disconnect|        | polite link down
  |                       +------------------->|       =/
  X                       |                    |
                          .                    .
                          .                    .

  - 'vs.' prefix indicates a visa service API call which runs on top of ZPR.
    All other messages are ZDP.
```

```
NOTES:

(1) The auth_connect message is not fully filled in. We just include a couple of
    claims: the adapater ZPR address and the CN from the adapter certificate.

(2) The echo/echo-resp stuff is just for keep alive and I'm not sure what actual
    ZDP messages we will use.  Note that we may want to establish liveness before
    calling auth_connect.  It is possible for the key management handshake to
    fail and one side not realize it.
    
(3) "raa" is RegisterAgentAddress in which the agent sends its ZPR address to the
    node. Required since the node includes this in the connect message to the 
    visa service.  "raar" is RegisterAgentAddressResponse.
    
(4) The "hello" and "hellor" (hello-response) messages are placeholders and do not
    transfer any information at the moment.
```



## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ZPR by you, shall be licensed as Apache 2.0, without any additional
terms or conditions.


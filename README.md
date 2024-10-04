# zpr-core
Core ZPR components

## Milestone 2 Startup Sequence

Here is the general "startup" sequence for milestone 2.

 * NODE - the only node
 * V/S ADAPTER - the adapter in front fo the visa service.
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
  .         .             |<--+                |
  .         .             |                    |
  |                       | hello              |       =\
  |                       +------------------->|        |
  |                       |         hello-resp |        | node establishes    
  |                       |<-------------------+        | connection to 
  |                       |                    |        | visa service
  |                       | authenticate       |        |
  |                       +------------------->|        |
  |                       |           response |        |
  |                       |<-------------------+        |
  .                       .                    .       =/
  .                       .                    .
  |                       |                    |
  |  kmh1                 |                    |       =\ 
  +---------------------->|                    |        | security 
  |                  kmh2 |                    |        | association
  |<----------------------+                    |       =/
  |                       |                    |
  |                       | auth_connect(1)    |       =\
  |                       +------------------->|        | node tell
  |                       |         auth_reply |        | visa service
  |                       |<-------------------+       =/
  |                       |                    |
  | echo(2)               |                    |       =\
  +---------------------->|                    |        | keep alive
  |             echo-resp |                    |        | connect check
  |<----------------------+                    |       =/
  |                       |                    |
  .                       .                    .
  . (traffic)             .                    .       =\
  +---------------------->| visa-req           |        | visa 
  |                       +------------------->|        | request
  |                       |         visa-resp  |        |
  |                       |<-------------------+       =/
  |                       |                    |
  .                       .                    .
  .                       .                    .
  | terminate             |                    |       =\
  +---------------------->| agent_disconnect   |        | polite link down
  |                       |------------------->|       =/
  X                       |                    |
                          .                    .
                          .                    .
```

```
NOTES:

(1) The auth_connect message is not fully filled in. We just include a couple of
    claims: the adapater ZPR address and the CN from the adapter certificate.

(2) The echo/echo-resp stuff is just for keep alive and I'm not sure what actual
    ZDP messages we will use.  Note that we may want to establish liveness before
    calling auth_connect.  It is possible for the key management handshake to
    fail and one side not realize it.
```



## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ZPR by you, shall be licensed as Apache 2.0, without any additional
terms or conditions.


# ZPR Milestone 3

## Setup

This runs on a small ZPR network set up in the cloud.  There is a single
node, there there are two services available: a web service and a
NextCloud service.


Clients:

- `fd5a:5052:2::100` - admin
- `fd5a:5052:2::101` - mathias
- `fd5a:5052:2::102` - sarah
- `fd5a:5052:2::103` - chris




## Network Configuration

### Physical (Substrate) Network Setup

M3 is set up on Oracle cloud.
Here is the **substrate** network setup. Each host has a private OCI
address and a public substrate address.

TODO: actually we only need a public substrate address on the node.
The rest can use their OCI private IP addresses.

DOCK ADDRESS = 129.153.152.175

```
     a node       runs adapter + visa service
    +-----+           +-----+
    |node |           | vs  |
    +--+--+           +--+--+
       |129.153.152.175  |132.226.62.127
       |10.0.0.21        |10.0.0.246
       |                 |
    ---+--------+--------+-------+--- network 10.0.0.0/24
                |                |
      10.0.0.201|                |10.0.0.54
  129.153.137.37|                |150.136.190.132
             +--+--+          +--+--+
             | nc  |          | ws  |
             +-----+          +--+--+
             runs adapter    runs adapter
             + nextcloud     + webserver

```

### ZPR Network Setup

Notes:
- The ZPR address space is `fd5a:5052::/32`
- The visa service (and its adapter) always get address `fd5a:5052::1`.
- The network `fd5a:5052:90de::/48` is reserved for nodes.
- Below we are using `fd5a:5052:1::/48` for all the non-visaservice adapters.

```
                fd5a:5052:90de::1
                (node)
                cn = node.zpr.org
     +-----+        +-----+        +-----+
     |     |        |     |        |     |
     | vs  +--------+node +--------+  ws |
     |     |        |     |        |     |
     +-----+        +--+--+        +-----+
   fd5a:5052::1        |         fd5a:5052:1::8
   (visa service)      |         (web server)
   cn = vs.zpr         |         cn = web.zpr.org
                       |
                    +--+--+
                    |     |
                    | nc  |
                    |     |
                    +-----+
                fd5a:5052:1::9
                cn = nc.zpr.org
```









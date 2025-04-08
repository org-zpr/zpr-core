# visa service

Started as a copy of the prototype ZPR visa service, but will evolve
independetly to meet the needs of the reference implementation.


## To build

Run `make` to build.  To run the tests do `make test`.

After a successful build the `vservice` binary will be found in
`core/build`.



## Visa Service Admin API

This is an HTTPS API for controlling the visa service designed for network
administrators. Access is protected by policy. The default port is TCP/8182 (see
`core/pkg/vservice/constants.go`), and this uses the ZPR contact address of the
adapter in front of the visa service.

The API code is in `core/pkg/vservice/admin.go`.

API returns `application/json`, unless there is an error.

The separate binary `vs-admin` (in the `vs-admin` subdirectory) is a command
line tool which uses the admin interface.


**API Summary**

| METHOD | PATH                                | EXPLAIN   |
| ------ | -----                               | -------   |
| GET    | `/admin/policies`                   | list policies    |
| POST   | `/admin/policy`                     | install a policy |
| GET    | `/admin/policy/{configID}/current`  | get the current policy for configuration |
| GET    | `/admin/visas`                      | list visas       |
| DELETE | `/admin/visas/{ID}`                 |  revoke a visa by its ID |
| GET    | `/admin/actors`                     | list connected actors    |
| DELETE | `/admin/actors/{CN}`                | revoke an actor (and all its visas) by adapter CN |
| POST   | `/admin/revokes`                    | administer the revocation table |
| GET    | `/admin/nodes`                      | list nodes |




### List policies `GET /admin/policies`

Returns:

```json
[
    {
        "config_id": 2024070200001,
        "version": "1712946177+localfile:policy-1n_2ds_1c.yaml:200d09643386decf3b13423cfeb36cd2a8b9a1ebc723e1cd0c292f23bb18201e"
    }
]
```

### Get current policy `GET /admin/policy/<CONFIG_ID>/current`

This takes a the `CONFIG_ID` as a path argument, eg:

```bash
GET /admin/policy/2024070200001/current
```

Returns:

```json
{
    "config_id": 2024070200001,
    "container": "H4sIAAAAAAAA/8 ..... (more base64 data omitted) ....QAA"
    "format": "base64;zip;41",
    "version": "1712946177"
}
```


### Install a policy `POST /admin/policy`

Takes a JSON encoded `PolicyBundle` struct (see `core/pkg/vservice/admin.go`)
filled in as follows:

```json
{
    "config_id": "",
    "version": "",
    "format": "base64;zip;41",
    "container": ".... (base 64, compressed, serialzed polio.PolicyBundle) ...",
}
```

Note that the `41` in the `format` field should be the current serialization ID for the policy schema.
In the code this is `SerialVersion` which can be found in `mods/polio/const.go`.

If you do set `version` then the admin service will ensure that the current
(running) policy matches the value before attempting to install the new policy.


Returns the config ID and version:

```json
{
    "config_id": 2024070200001,
    "version": "171294623+92310299"
}
```

### List visas `GET /admin/visas`

Returns a brief summary of each live visa. Note that unlike all other time values in the API which are
seconds since the epoch, the expiration value on visas is **milliseconds** since the epoch.


Returns:

```json
[
    {
        "dest": "127.0.0.1",
        "expires": 1738991722149,
        "id": 8,
        "source": "fd5a:5052:90de::1"
    },
    {
        "dest": "fd5a:5052:90de::1",
        "expires": 1738991842150,
        "id": 9,
        "source": "127.0.0.1"
    }
]
```


### List actors `GET /admin/actors`

Get a brief summary of connected actors.


Returns:

```json
[
    {
        "cn": "vs.zpr",
        "ctime": 1738948830,
        "ident": "bee171ebaf1741b2c9879c730ed4abe0873ff42a25b116e74be6ef71be7322ee",
        "node": false,
        "zpr_addr": "127.0.0.1"
    },
    {
        "cn": "node.zpr.org",
        "ctime": 1738948942,
        "ident": "36e16f0a83c9a3274ce991f7561b1b445910de5c8cbb16b1e7f9de166f34342d",
        "node": true,
        "zpr_addr": "fd5a:5052:90de::1"
    }
]
```


### List nodes `GET /admin/nodes`

Get a brief summary of connected nodes.


Returns:

```json
[
    {
        "cn": "node.zpr.org",
        "connect_requests": 0,
        "ctime": 1738948942,
        "in_sync": true,
        "last_contact": 1738949250,
        "pending": 0,
        "visa_requests": 0,
        "zpr_addr": "fd5a:5052:90de::1"
    }
]
```


### Revoke visas by ID `DELETE /admin/visas/{ID}`

Send a delete request to revoke a visa by its issuer ID.

```bash
DELETE /admin/visas/22
```

Returns:

```json
{
    "revoked": "22",
    "count": 1
}
```

### Revoke CN access and associated visas `DELETE /admin/actors/{CN}`

Sends a delete request to revoke access to an adapter by its CN. Also revokes
any visas associatd with the adapter.

```bash
DELETE /admin/actors/foo.zpr.org
```

Returns:

```jason
{
    "revoked": "foo.zor.org",
    "count": 8,
}
```

Where `count` is the number of visas that were revoked.


### Clear the revocations table `/admin/revokes`

The visa service keeps track of recovations when they are made on adapter CNs or
authtication keys.  To clear the revocation table you can post a message to
`/admin/revokes`.

The JSON object to send looks like:

```json
{
    "clear_all": true
}

```

The return value includes the number of entries removed from the revocation table, for example:

```json
{
    "clear_count": 10
}
```


## Visa Service API

The main visa service api (for requesting visas and connection control) is a
THRIFT API. This runs on TCP/5002 by default. See `vs.thrift` in the
zpr-vsapi repo for documentation.




## Protocol Buffers

The compiled protocol buffers are included in source, but if you need to rebuild
them you must install:

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

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



## Visa Service API

The main visa service api (for requesting visas and connection control) is a
THRIFT API. This runs on TCP/5002 by default. See `thrift/vs.thrift` for
documentation.




## Protocol Buffers

The compiled protocol buffers are included in source, but if you need to rebuild
them you must install:

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```


## Thrift

The compiled thrift files are included in the source, but if you need to rebuild
them then you will need the thrift compiler.

```
cd thrift
THRIFTCC=/path/to/thrift/compiler make
make install-go
make install-rs
```


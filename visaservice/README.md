# visa service

Started as a copy of the prototype ZPR visa service, but will evolve
independetly to meet the needs of the reference implementation.


## To build

Run `make` to build.  To run the tests do `make test`.

After a successful build the `vservice` binary will be found in
`core/build`.



## Protocol Buffers

The compiled protocol buffers are included in source, but if you need to
rebuild them you must install:

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```


## Thrift

The compiled thrift files are included int he source, but if you need to
rebuild them then you will need the thrift compiler.

```
cd thrift
THRIFTCC=/path/to/thrift/compiler make
make install-go
make install-rs
```


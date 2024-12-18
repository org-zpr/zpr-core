# vs-conform: The Visa Service Conformance Tester

## Usage 

First start up a local visa service (without ZPR):

```bash
./core/build/vservice \
    -c ../examples/milestone2/vs/vs-config.yaml \
    -p ../examples/milestone2/policies/policy-m2-ping-and-http.bin \
    --listen_addr 127.0.0.1:12345
```

Then you run the tester by telling it the visa service port, address and the
node certificate.

```bash
 ./vs-conform -v 12345 127.0.0.1 ../../examples/milestone2/node/node-cert.pem

```

The visa service and tester use port TCP/8182 for the HTTPS admin interface by
default.

By default the tester will run through its complete (but small) set of tests.
To run a specific test, use the `-t` arg:

```bash
 ./vs-conform -t helloreps -v 12345 127.0.0.1 ../../examples/milestone2/node/node-cert.pem

```

The tester writes log messages to `conform.log`.

# pregen - Generated Integration Test Files

Various files pre-generated for running the integration tests.



## How to compile the policies



### Conformance test

Just need to compile the policy:

```bash
$ ../../compiler/target/debub/zpc -k zpr-rsa-key.pem conform-policy.zpl
```

### The "one-node" tests

```bash
../../compiler/target/debug/zpc -k zpr-rsa-key.pem v4-1node-2agent-ping.zpl
../../compiler/target/debug/zpc -k zpr-rsa-key.pem v4-1node-3agent-ping.zpl
```

Note that the v6 tests uses the same policy as the v4 tests but just
require a different configuration.  So,

```bash
../../compiler/target/debug/zpc -c v6-1node-2agent-ping.zplc -k zpr-rsa-key.pem -o v6-1node-2agent-ping.bin v4-1node-2agent-ping.zpl
../../compiler/target/debug/zpc -c v6-1node-3agent-ping.zplc -k zpr-rsa-key.pem -o v6-1node-3agent-ping.bin v4-1node-3agent-ping.zpl
```


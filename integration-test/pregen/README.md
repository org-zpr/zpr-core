# pregen - Generated Integration Test Files

Various files pre-generated for running the integration tests.


## How to compile the policies

Can use the incuded `Makefile`.  


### Conformance test

Just need to compile the policy:

```bash
zpc -k zpr-rsa-key.pem conform-policy.zpl
```

### The "one-node" tests

```bash
zpc -k zpr-rsa-key.pem v4-1node-2actor-ping.zpl
zpc -k zpr-rsa-key.pem v4-1node-3actor-ping.zpl
```

Note that the v6 tests uses the same policy as the v4 tests but just
require a different configuration.  So,

```bash
zpc -c v6-1node-2actor-ping.zplc -k zpr-rsa-key.pem -o v6-1node-2actor-ping.bin v4-1node-2actor-ping.zpl
zpc -c v6-1node-3actor-ping.zplc -k zpr-rsa-key.pem -o v6-1node-3actor-ping.bin v4-1node-3actor-ping.zpl
```


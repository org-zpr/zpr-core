# Configuration files for Milestone 2

## Legacy keys 

There are some keys in here that are only needed due to reliance on some
older protype code-

- node-rsa cert and key: These are used to sign a challenge from the
  visa service, and the cert is sent to the visa service for checking.
  (Note: as of 10/3/2024 the visa service does not check the cert.)

- zpr-rsa cert and key: The visa service expects that policies are
  signed with this key (so it is also required for compiling policies
  with the legacy compiler).  Visa service also uses this key to sign
  its authentication tokens (the JWTs).  Finally, the visa service uses
  this key for the TLS gRPC channel to the "admin service" -- which is a
  legacy command line tool.

It's possible we can remove some of these keys prior to milestone two.
Related github issues:

- https://github.com/org-zpr/zpr-core/issues/140
- https://github.com/org-zpr/zpr-core/issues/139


## Manual Testing

You can fairly easily test some of the visa service (VS) and visa support
service (VSS) interactions using just the visa service and the `cli` tool.

Shown here using the baked in configs in this directory.

### Compiler the policy

```bash
cd policies
/path/to/zpr-prototype/cmd/zplc/zplc -k ../zpr-rsa-key.pem ./policy-m2.yaml
```


### Bring up the visa service
    
```bash
cd /path/to/zpr-core/visaservice/core/build
./vservice --verbose \
    --conf ../../../examples/milestone2/vs-config.yaml \
    --policy ../../../examples/milestone2/policies/policy-m2.bin
```

### Bring up a VSS in its own terminal

```bash
cd /path/to/zpr-core/visaservice/cli
./target/debug/cli runvss --zpr-addr fd5a:5052:90de::1
```


### Authenticate with the visa service

```bash
cd /path/to/zpr-core/visaservice/cli
./target/debug/cli authenticate \
    --cert ../../examples/milestone2/node-rsa-cert.pem \
    --key ../../examples/milestone2/node-rsa-key.pem \
    --zpr-addr fd5a:5052:90de::1 \
    --node-name n0
```

The authentication should succeed, and you should see the VSS log that two visas
have been pushed (that would be a visa allowing the Node to talk to the Visa
Service, and a visa allowing the Visa Service to talk to the Nodes Visa Support
Service).


### Issue a connect call (for the service adapter in policy)

_TODO_


### Issue a connect call (for a fake client adapter)

_TODO_


### Request a visa for client to service

_TODO_



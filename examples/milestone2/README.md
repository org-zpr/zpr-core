# Configuration files for Milestone 2

## Legacy keys 

There are some keys in here that are only needed due to reliance on some
older protype code-

- zpr-rsa cert and key: The visa service expects that policies are
  signed with this key (so it is also required for compiling policies
  with the legacy compiler).  Visa service also uses this key to sign
  its authentication tokens (the JWTs).  Finally, the visa service uses
  this key for the TLS gRPC channel to the "admin service" -- which is a
  legacy command line tool.

It's possible we can remove some of these keys prior to milestone two.
Related github issues:

- https://github.com/org-zpr/zpr-core/issues/140


## Manual Testing

You can fairly easily test some of the visa service (VS) and visa support
service (VSS) interactions without any ZPR or ZDP using just the visa service
and the `cli` tool.

Shown here using the baked in configs in this directory.

For this to work, you need to add some IP aliases addresses to your host.

* The visa service address, `fd5a:5052::1` (is hard-coded, well known address).
* The node address, `fd5a:5052:90de::1` (must match policy).
* The service address, `10.1.0.8` (must match policy).


### Compile the policy

Note the correct version of `zplc` to use is in the `zpr-prototype` repo
in the `refimpl-m2` branch.


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
    --cert ../../examples/milestone2/node-cert.pem \
    --zpr-addr fd5a:5052:90de::1 \
    --node-name n0
```

The authentication should succeed, and you should see the VSS log that two visas
have been pushed (that would be a visa allowing the Node to talk to the Visa
Service, and a visa allowing the Visa Service to talk to the Nodes Visa Support
Service).

Authenticate also returns an API key, it will be on the line starting with `RESULT`:

```bash
sending HELLO
HELLO OK
authenticate sent!
result = "063bb4a7-f2b7-4ee0-83c1-57d959ea75b8"
Authenticate command executed successfully
```

In this case, the API key is `"063bb4a7-f2b7-4ee0-83c1-57d959ea75b8`.

It is convenient to put that in an environment variable like so:

```bash
export ZAPIKEY=063bb4a7-f2b7-4ee0-83c1-57d959ea75b8
```


### Issue a connect call (for the service adapter in policy)

```bash
./target/debug/cli authorize-connect -a $ZAPIKEY --node-zpr-addr fd5a:5052:90de::1 -c zpr.addr=10.1.0.8 -c zpr.adapter.cn=service.zpr.org
```



### Issue a connect call (for a fake client adapter)

```bash
./target/debug/cli authorize-connect -a $ZAPIKEY --node-zpr-addr fd5a:5052:90de::1 -c zpr.addr=10.1.0.10 -c zpr.adapter.cn=client.zpr.org
```


### Request a visa for client to service


```bash
./target/debug/cli requestvisa -a $ZAPIKEY --tcp '10.1.0.10:31337>10.1.0.8:80[S]'
```



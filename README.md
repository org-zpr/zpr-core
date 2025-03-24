# zpr-core
Core ZPR components

We are currently working towards Milestone 3.  
- See the [current iteration and backlog](https://github.com/orgs/org-zpr/projects/1/views/3).
- See the [roadmap](https://github.com/orgs/org-zpr/projects/3/views/6).


## Build Notes

The thrift generated code comes from its own repository, you need to do a little
configuration in order for the build system to download it:

Developers will have to either run `git config --global url.git@github.com:.insteadOf https://github.com/`
(which ends up in ~/.gitconfig), (or configure a PAT and use git askpass like
the runners now do). Also, anyone developing Golang will have to set `go env -w GOPRIVATE="github.com/org-zpr/*"`
(which ends up in ~/.config/go/env). Again, once we're public this requirement
goes away.


## How to setup a ZPRnet

A minimal ZPRnet has a node and a visa service. You will probably also
want a service or two that run on the net, plus some client adapters
that connect in and access the services.


1. Create a certificate authority keypair.
2. Create a "zpr" RSA keypair (used for signing policy and more)
3. Create Noise keys and signed certificates for all adapters and the
   node.
4. Create a configuration file for your node.
5. Create a configuration file for your visa service and its adapter.
6. Write a policy and compile it.
7. Start up the node, the visa service and the visa service adapter.

### Create a certificate authority keypair

We'll put the authority related file into a directory named `authority`.
You will be prompted for a pass phrase. You'll need to use that whenever
you sign a certificate using the authority key.

```bash
mkdir authorita
cd authority
openssl genrsa -aes256 -out auth-ca.key 4096
openssl req -x509 -new -nodes -key auth-ca.key -sha256 -days 1826 -out auth-ca.crt
```

### Createa a "zpr" RSA keypair

This key and its usage is required because we are still using the
prototype Visa Service.  We just create a key and sign it using our
recently created authority.

```bash
# Create the key
openssl genrsa -out zpr-rsa-key.pem 2048

# Create the certificate request
openssl req -new -key zpr-rsa-key.pem -out zpr.csr
```

Then use the authority created earlier to generate a certificate. Note that this 
certificate will be used for signing policies and for using TLS on the admin 
interface so you need to add some extensions when you generate the certificate.

Create a file named `sign.ext` and with these contents (replace the '*.zpr.org' with
a domain you are using):

```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = DNS:*.zpr.org
```

Then create the certificate:

```bash
openssl x509 -req -in zpr.csr -CA auth-ca.crt -CAkey auth-ca.key -CAcreateserial \
  -out zpr-rsa.crt -days 1825 -sha256 -extfile sign.ext
```

### Create Noise keys and signed certificates for all

Use the `tools/zpr-pki` tool to create NOISE keys for all the participants:
- `./zpr-pki >node-noise.key`
- `./zpr-pki >adapter-vs-noise.key`
- (and so on for other adapters)

Once you have private key (PEM) files, you need to create certificates as follows:

```bash
./zpr-pki pubkey <node-noise.key >node-noise-pub.pem
./zpr-pki gensignedcert authority/auth-ca.crt authority/auth-ca.key \
  /CN=node.zpr.org 365 < node-noise-pub.pem >node-noise.crt
```
Do that for all the NOISE keys you have. Note that the visa servcie NOISE certificate 
**must** use `vs.zpr` for its CN.


### Create a configuration file for your node.

Assuming:
- Node substrate (dock) address is `129.6.7.1`
- Node ZPR address is `fd5a:5052:90de::1`

Sample configuration, place in a file named `node-conf.toml`.

```toml
[global]
name = "node"
ca_file = "auth-ca.crt"
certificate_file = "node-noise.crt"
private_key_file = "node-noise.key"
self_addr = "129.6.7.1:5000"
agent_addr = [ "fd5a:5052:90de::1" ]
tun_if = "tun9"
```

Note that the key and certificate files referenced in the node configuration must
be present in the same directory as the configuration file.


### Create a configuration file for your visa service and its adapter.

Place the visa service configuration in a file named, `vs-config.yaml`.

```yaml
adapter_cert: adapter-vs-noise.crt
root_ca: auth-ca.crt
disable_connect_validation: true
vs_cert: zpr-rsa.crt
vs_key: zpr-rsa-key.pem
```

The adapter for the visa service needs to know the substrate address of the node
which above we set to `129.6.7.1`.

The visa service adapter configuration should go in `adapter-vs-conf.toml`:

```toml
[global]
name = "vs"
ca_file = "auth-ca.crt"
certificate_file = "adapter-vs-noise.crt"
private_key_file = "adapter-vs-noise.key"
agent_addr = [ "fd5a:5052::1" ] # visa service well known addr
self_addr = "0.0.0.0:5000"
tun_if = "tun9"

[adapter]
node_addr = "129.6.7.1:5000"
node_public_key_file = "node-noise-pub.pem"
```

Note that the key and certificate files referenced in the configuration files
be present in the same directory as the configuration file.

### Write a policy and compile it.

(TODO)


### Start up the node, the visa service and the visa service adapter.

(TODO)









## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in ZPR by you, shall be licensed as Apache 2.0, without any additional
terms or conditions.


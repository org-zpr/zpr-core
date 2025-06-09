# vs-client

A toy client for the visa service. This is for playing with the visa service 
API during development.



## Usage

First start the visa service locally (ie, without ZPR running).  (Use 
something like `-l 127.0.0.1:31337`).

Pass `-h` to get the list of available commands.


### Examples

Try hello:

```bash
./vs-client hello --service localhost:31337
```

Or authenticate, which will return an API key.

```bash
./vs-client authenticate -s localhost:31337 -c flubber=rubber -c fee=flop --cert ./cert.pem --key ./key.pem
```

- you need a certificate and a private key.
- use `-c` to pass claims.


Now you can de-register:

```bash
./vs-client deregister -s localhost:31337 -a f53ef984-d6d6-40c2-abe9-35d82eeabfb2
```

- Subtitute your API key (the `-a` arg) in the above command.




### Notes

- In order to get full usage you may need to add some IP addresses to your 
  local interface and/or use a specially crafted policy.



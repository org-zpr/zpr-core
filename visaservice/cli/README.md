# visaservice example client

This is for playing with the visa service API during development.



## Usage

First start the visa service locally (ie, without ZPR running).  (Use something like `-l 127.0.0.1:31337`).


Then try hello:

```bash
./cli hello --service localhost:31337
```

Or authenticate, which will return an API key.

```bash
./cli authenticate -s localhost:31337 -c flubber=rubber -c fee=flop --cert ./cert.pem --key ./key.pem
```

- you need a certificate and a private key.
- use `-c` to pass claims.


Now you can de-register:

```bash
./target/debug/cli deregister -s localhost:31337 -a f53ef984-d6d6-40c2-abe9-35d82eeabfb2
```

- Subtitute your API key (the `-a` arg) in the above command.



## Comming soon!
The rest of the visa service API (see the `../thrift/vs.thrift` file)

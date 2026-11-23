# libnode2

The new Cap'n Proto RPC interface for the VS-API and VSS-API.

WORK IN PROGRESS.



## Testing

If you build with `--features build-lnt` you get a binary that can be
used to do basic testing against a running visa service.

You can start the V2 Visa Service on localhost by setting its `vs_addr`
to `"::1"` in your `vs.toml`.


Example using the test data:

Start visa service (assuming you have renamed `vs.toml` to `vs-local.toml`).

```bash
/path/to/vs -c vs-local.toml test-data/test.bin2
```

Then launch lntest:


```bash
./target/degug/lntest -a \[::1\]:5002 -n node.zpr.org \
  -p test-data/include/node-private-key.pem \
  --substrate-addr 127.0.0.1:5000
```

Hit return a few times becuase the REPL loop get clobbered by the logging
output.  Then type "h" for help.


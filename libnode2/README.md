# libnode2

The new Cap'n Proto RPC interface for the VS-API and VSS-API.

WORK IN PROGRESS as of November 2025.



## Testing

If you build with `--features build-lnt` you get a binary that can be
used to do basic testing against a running visa service.

You can start the V2 Visa Service on localhost by setting its `vs_addr`
to `"::1"` in your `vs.toml`.


Example run:

```bash
./target/degug/lntest -a \[::1\]:5002 -n some.valid.cn \
  -p path/to/private-key.pem
```



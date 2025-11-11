# libnode2

The new Cap'n Proto RPC interface for the VS-API and VSS-API.

WORK IN PROGRESS as of November 2025.



## Testing

If you build with `--features build-ln2` you get a binary that can be
used to do basic testing against a running visa service.

The new visa service has a hard coded RSA public key corresponding to
the key in `test-data/rsa-node.test.zpr-private.pem`.  To trigger the
use of that you must pass in a CN of `node.test.zpr`.

You can start the V2 Visa Service on localhost by setting its `vs_addr`
to `"::1"` in your `vs.toml`.


Example run:

```bash
./target/degug/ln2 -a \[::1\]:5002 -n node.test.zpr \
  -p test-data/rsa-node.test.zpr-private.pem
```



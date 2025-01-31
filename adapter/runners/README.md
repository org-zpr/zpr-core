# runners

Wrapper programs to make it easy to launch a node or adapter.

The only benfit to using these over the `ph` binary is that these set up
the local TUN inteface for you.



## Usage

Given a node configuration file, say "mynode.toml", you can start a node
with:

```bash
sudo ./node -c mynode.toml
```

That only works if `ph` binary is in your path.  You can tell the runner
where the binary is:

```bash
sudo ./node -c mynode.toml /path/to/ph
```

Usage is the same for the `adapter` wrapper.


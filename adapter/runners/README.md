# runners

Wrapper programs to make it easy to launch a node or adapter.

These take care of setting up the TUN interface (but do not tear it down), as
well as ensuring that the path for the control socket is created.

Although you need to run these as root, they drop root before starting
the packet handler. 


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

Usage is the same for the `adapter` wrapper.  Pass `--help` for help.



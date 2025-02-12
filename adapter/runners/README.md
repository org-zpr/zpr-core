# runners

Wrapper programs to make it easy to launch a node or adapter.

These set up the local environment:

* On linux, take care of setting up the TUN interface (but do not tear it
down).
* Ensure that the path for the control socket is created.

You need to run these as root so that the TUN interface can be
manipulated.  On linux this drops root privileges before starting the ph.
On mac we keep root since the ph itself needs to bring up the TUN.


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



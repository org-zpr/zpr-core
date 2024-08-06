Various "extensions" to external crates.

The module structure here mirrors that of each individual crate.

Most of the extensions are in the form of traits named as `FooExt`, where
`Foo` is the type or trait which is being extended.

Each feature flag is the name of a library the user is already using
and would like to have "extended".

Extensions which exist include:

* backports of certain nightly-only experimental APIs
* Vec backing store recycling
* scoped destructors
* support for certain extra socket options / ioctls of network devices
* support for TUN device per-packet packet information
* methods for transferring data from/to `bytes::Buf`/`BufMut` objects

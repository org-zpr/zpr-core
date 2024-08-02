

all: check build


all-go: check-go build-go


all-rs: check-rs build-rs


clean:
	$(MAKE) -C core $@
	cd cli && cargo clean

build:
	cd mods && $(MAKE)
	cd core && $(MAKE)
	cd cli && cargo build


build-go:
	cd mods && $(MAKE)
	cd core && $(MAKE)


build-rs:
	cd cli && cargo build


test:
	$(MAKE) -C mods $@
	$(MAKE) -C core $@
	cd cli && cargo test


test-go:
	$(MAKE) -C mods test
	$(MAKE) -C core test


test-rs:
	cd cli && cargo test


# If check fails, the thrift files need to be rebuilt
check: check-go check-rs


check-go:
	$(MAKE) -C core check


# In the node project we have a cargo build script to check the MD5s.
# Since there is a makefile for the whole visa service it is much 
# simpler to do this here instead of in our `cli` subproject.
check-rs:
	cd thrift && md5sum -c ../cli/src/vsapi/vs.thrift.sum



.PHONY: all build test clean all-go build-go build-rs test-rs test-go check check-go check-rs

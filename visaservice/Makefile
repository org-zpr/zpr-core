

all: build


all-go: build-go


all-rs: build-rs


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



.PHONY: all build test clean all-go build-go build-rs test-rs test-go

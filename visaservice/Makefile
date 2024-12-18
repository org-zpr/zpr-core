all: build

all-rs: build-rs

all-go: build-go

test: test-rs test-go

clean:
	$(MAKE) -C core $@
	$(MAKE) -C mods $@
	$(MAKE) -C vs-client $@
	$(MAKE) -C vs-admin $@
	$(MAKE) -C vs-conform $@

build:
	$(MAKE) -C mods all
	$(MAKE) -C core all
	$(MAKE) -C vs-client all
	$(MAKE) -C vs-admin all
	$(MAKE) -C vs-conform all

build-go:
	$(MAKE) -C mods all
	$(MAKE) -C core all
	$(MAKE) -C vs-conform all

build-rs:
	$(MAKE) -C vs-client all
	$(MAKE) -C vs-admin all

test-go:
	$(MAKE) -C mods test
	$(MAKE) -C core test
	$(MAKE) -C vs-conform test

test-rs:
	$(MAKE) -C vs-client test
	$(MAKE) -C vs-admin test

.PHONY: all all-rs all-go test clean build build-go build-rs test-go test-rs

all: build

all-rs: build-rs

all-go: build-go

test: test-rs test-go

clean:
	$(MAKE) -C core $@
	$(MAKE) -C mods $@
	$(MAKE) -C cli $@
	$(MAKE) -C admin $@

build:
	$(MAKE) -C mods all
	$(MAKE) -C core all
	$(MAKE) -C cli all
	$(MAKE) -C admin all

build-go:
	$(MAKE) -C mods all
	$(MAKE) -C core all

build-rs:
	$(MAKE) -C cli all
	$(MAKE) -C admin all

test-go:
	$(MAKE) -C mods test
	$(MAKE) -C core test

test-rs:
	$(MAKE) -C cli test
	$(MAKE) -C admin test

.PHONY: all all-rs all-go test clean build build-go build-rs test-go test-rs

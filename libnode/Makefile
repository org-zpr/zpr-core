

.PHONY: all build test clean dist-clean

all: build


build:
	cargo build

test: build
	cargo test --verbose

clean:
	cargo clean

dist-clean: clean

.DEFAULT_GOAL := all

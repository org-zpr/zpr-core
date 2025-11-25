
.PHONY: all build test clean check

all: build

build:
	cargo build --all-targets
	cargo build --features build-lnt

test:
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings

clean:
	cargo clean

.DEFAULT_GOAL := all

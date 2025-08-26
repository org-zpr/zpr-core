.PHONY: all
all: build

.PHONY: build
build:
	cargo build --verbose

.PHONY: release
release:
	cargo build -r

.PHONY: test
test:
	cargo test --verbose

.PHONY: clean
clean:
	cargo clean
	rm -r extensions

.PHONY: generate
generate:
	./target/debug/ph-cli --generate


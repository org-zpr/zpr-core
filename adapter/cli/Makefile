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

# Create the completion scripts for the CLI
TARGET_DIR = extensions

.PHONY: generate
generate:
	@if [ -d "$(TARGET_DIR)" ] ; then rm -r "$(TARGET_DIR)" ; fi
	mkdir "$(TARGET_DIR)"
	./target/debug/ph-cli --generate


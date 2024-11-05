.PHONY: all
all: build


.PHONY: build
build:
	cargo build --verbose

.PHONY: test
test:
	cargo test --verbose && cargo test --lib --verbose

.PHONY: lib
lib:
	cargo build --lib

.PHONY: clean
clean:
	cargo clean


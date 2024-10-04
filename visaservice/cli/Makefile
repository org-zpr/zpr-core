



src/vsapi/mod.rs: thrift

.PHONY: all clean dist-clean build test thrift

all: build


clean:
	cargo clean

dist-clean: clean
	rm -rf src/vsapi/mod.rs


build: src/vsapi/mod.rs
	cargo build


test:
	cargo test


thrift:
	mkdir -p src/vsapi
	$(MAKE) -C ../thrift rs
	cp ../thrift/gen-rs/vs.rs src/vsapi/mod.rs

.DEFAULT_GOAL := all


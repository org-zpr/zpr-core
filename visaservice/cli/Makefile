



src/vsapi/mod.rs: thrift

../../libnode/src/vsapi/mod.rs: libnode-thrift

.PHONY: all clean dist-clean build test thrift libnode-thrift

all: build


clean:
	cargo clean

dist-clean: clean
	rm -rf src/vsapi/mod.rs


build: src/vsapi/mod.rs ../../libnode/src/vsapi/mod.rs
	cargo build


test:
	cargo test


thrift:
	mkdir -p src/vsapi
	$(MAKE) -C ../thrift rs
	cp ../thrift/gen-rs/vs.rs src/vsapi/mod.rs

libnode-thrift:
	$(MAKE) -C ../../libnode thrift


.DEFAULT_GOAL := all




src/vsapi/mod.rs: thrift


.PHONY: all build test thrift clean dist-clean

all: build


build: src/vsapi/mod.rs
	cargo build

test:
	cargo test --verbose

thrift:
	mkdir -p src/vsapi
	$(MAKE) -C ../visaservice/thrift rs
	cp ../visaservice/thrift/gen-rs/vs.rs src/vsapi/mod.rs


clean:
	cargo clean


dist-clean: clean
	rm -rf src/vsapi


.DEFAULT_GOAL := all

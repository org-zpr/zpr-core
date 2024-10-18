

.PHONY: all clean build libnode test

all: build


clean:
	cargo clean


build: libnode
	cargo build

libnode:
	$(MAKE) -C ../../libnode

test:
	cargo test




.DEFAULT_GOAL := all


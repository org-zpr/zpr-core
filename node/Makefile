



.PHONY: all build test clean libnode ph

all: build


build: libnode ph
	cargo build

libnode:
	$(MAKE) -C ../libnode 

ph:
	$(MAKE) -C ../adapter/ph lib

test:
	cargo test --verbose


clean:
	cargo clean



.DEFAULT_GOAL := all

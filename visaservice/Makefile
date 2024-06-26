

all: build

clean: 
	$(MAKE) -C core $@
	cd cli && cargo clean

build:
	cd mods && $(MAKE)
	cd core && $(MAKE)
	cd cli && cargo build


test:
	$(MAKE) -C mods $@
	$(MAKE) -C core $@
	cd cli && cargo test


.PHONY: all build test clean

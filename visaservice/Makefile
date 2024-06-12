

all: build

clean: 
	$(MAKE) -C core $@

build:
	cd mods && $(MAKE)
	cd core && $(MAKE)


test:
	$(MAKE) -C mods $@
	$(MAKE) -C core $@


.PHONY: all build test clean

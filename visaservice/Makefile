

.PHONY: all
all: build



.PHONY: build
build:
	cd mods && $(MAKE)
	cd core && $(MAKE)


.PHONY: test
test:
	cd mods && $(MAKE) test
	cd core && $(MAKE) test

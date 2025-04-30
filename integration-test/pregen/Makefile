ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := conform-policy.bin v4-1node-2actor-ping.bin v4-1node-3actor-ping.bin v6-1node-2actor-ping.bin v6-1node-3actor-ping.bin

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean - removes all the .bin policy files
	@echo make all   - recompiles out of date policy files
	@echo
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

v6-1node-2actor-ping.bin: v6-1node-2actor-ping.zplc v4-1node-2actor-ping.zpl
	$(ZPLC) -c v6-1node-2actor-ping.zplc -k $(KEY) -o $@ v4-1node-2actor-ping.zpl


v6-1node-3actor-ping.bin: v6-1node-3actor-ping.zplc v4-1node-3actor-ping.zpl
	$(ZPLC) -c v6-1node-3actor-ping.zplc -k $(KEY) -o $@ v4-1node-3actor-ping.zpl


%.bin: %.zpl %.zplc
	$(ZPLC) -k $(KEY) $<


.PHONY: all clean

.DEFAULT_GOAL: info

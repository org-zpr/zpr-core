ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := v4-1node-2actor-ping.bin2 v4-1node-3actor-ping.bin2 v6-1node-2actor-ping.bin2 v6-1node-3actor-ping.bin2

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean   - removes all the .bin2 policy files
	@echo make all     - recompiles out of date policy files
	@echo make rebuild - run a clean followed by an all.
	@echo
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

rebuild: clean all

v6-1node-2actor-ping.bin2: v6-1node-2actor-ping.zplc v4-1node-2actor-ping.zpl
	$(ZPLC) -c v6-1node-2actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-2actor-ping.zpl


v6-1node-3actor-ping.bin2: v6-1node-3actor-ping.zplc v4-1node-3actor-ping.zpl
	$(ZPLC) -c v6-1node-3actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-3actor-ping.zpl


%.bin2: %.zpl %.zplc
	$(ZPLC) -k $(KEY) $<


.PHONY: all clean rebuild

.DEFAULT_GOAL: info

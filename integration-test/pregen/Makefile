ZPC := ../../compiler/target/debug/zpc
KEY := zpr-rsa-key.pem

OBJS := conform-policy.bin v4-1node-2agent-ping.bin v4-1node-3agent-ping.bin v6-1node-2agent-ping.bin v6-1node-3agent-ping.bin

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean - removes all the .bin policy files
	@echo make all   - recompiles out of date policy files
	@echo
	@echo Requires that compiles is built in debug target.
	@echo Or you can set path to zpc by setting ZPC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

v6-1node-2agent-ping.bin: v6-1node-2agent-ping.zplc v4-1node-2agent-ping.zpl
	$(ZPC) -c v6-1node-2agent-ping.zplc -k $(KEY) -o $@ v4-1node-2agent-ping.zpl


v6-1node-3agent-ping.bin: v6-1node-3agent-ping.zplc v4-1node-3agent-ping.zpl
	$(ZPC) -c v6-1node-3agent-ping.zplc -k $(KEY) -o $@ v4-1node-3agent-ping.zpl


%.bin: %.zpl %.zplc
	$(ZPC) -k $(KEY) $<


.PHONY: all clean

.DEFAULT_GOAL: info

# Requires that env var $THRIFTCC is set to location of thrift compiler.

# VSAPI is the visa service API.
# Used by:
#   - visa service go code (server)
#   - visa service debug client (client)
#   - node visa service client (client)
VS_DEST_GO := ../core/pkg/vsapi
VS_DEST_RS_CLI := ../cli/src/vsapi
VS_DEST_RS_NODE := ../../node/src/vsapi


# VSSAPI is the visa service support API
# Used by:
#   - visa service go code (client)
#   - node (server)
VSS_DEST_GO := ../core/pkg/vssapi
VSS_DEST_RS_NODE := ../../node/src/vssapi


# Build output directories for the go and rust
BUILD_GO := gen-go
BUILD_RS := gen-rs


VS_SUM := vs.thrift.sum
VSS_SUM := vss.thrift.sum

SUMS := $(patsubst %.thrift,%.thrift.sum,$(wildcard *.thrift))

ifndef THRIFTCC
  $(error must set THRIFTCC to location of thrift compiler)
endif




all: go rs


install: install-go install-rs


go: $(BUILD_GO)/vsapi $(BUILD_GO)/vssapi


rs: $(BUILD_RS)/vs.rs $(BUILD_RS)/vss.rs


sums: $(SUMS)


install-go: sums go
	test -d $(VS_DEST_GO)  || mkdir $(VS_DEST_GO)
	test -d $(VSS_DEST_GO) || mkdir $(VSS_DEST_GO)
	cp $(BUILD_GO)/vsapi/*.go  $(VS_DEST_GO)
	cp $(VS_SUM)          $(VS_DEST_GO)
	cp $(BUILD_GO)/vssapi/*.go $(VSS_DEST_GO)
	cp $(VSS_SUM)         $(VSS_DEST_GO)


install-rs: sums rs
	cp $(BUILD_RS)/vs.rs  $(VS_DEST_RS_CLI)/mod.rs
	cp $(VS_SUM)     $(VS_DEST_RS_CLI)
	cp $(BUILD_RS)/vs.rs  $(VS_DEST_RS_NODE)/mod.rs
	cp $(VS_SUM)     $(VS_DEST_RS_NODE)
	cp $(BUILD_RS)/vss.rs $(VSS_DEST_RS_NODE)/mod.rs
	cp $(VSS_SUM)    $(VSS_DEST_RS_NODE)


$(BUILD_GO)/vsapi: vs.thrift
	mkdir -p $(BUILD_GO)
	$(THRIFTCC) -r -out $(BUILD_GO) --gen go $<


$(BUILD_GO)/vssapi: vss.thrift
	mkdir -p $(BUILD_GO)
	$(THRIFTCC) -r -out $(BUILD_GO) --gen go $<


$(BUILD_RS)/vs.rs: vs.thrift
	mkdir -p $(BUILD_RS)
	$(THRIFTCC) -r -out $(BUILD_RS) --gen rs $<


$(BUILD_RS)/vss.rs: vss.thrift
	mkdir -p $(BUILD_RS)
	$(THRIFTCC) -r -out $(BUILD_RS) --gen rs $<


$(SUMS): %.thrift.sum: %.thrift
	md5sum $< >$@


clean:
	rm -rf $(BUILD_GO) && rm -rf $(BUILD_RS) && rm -f $(SUMSFILE)


.PHONY: all go rs install install-go install-rs clean sums

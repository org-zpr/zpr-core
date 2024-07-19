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
GGO := gen-go
GRS := gen-rs



ifndef THRIFTCC
  $(error must set THRIFTCC to location of thrift compiler)
endif


all: go rs


go: $(GGO)/vsapi $(GGO)/vssapi


rs: $(GRS)/vs.rs $(GRS)/vss.rs


install-go: go
	test -d $(VS_DEST_GO) || mkdir $(VS_DEST_GO)
	cp $(GGO)/vsapi/*.go $(VS_DEST_GO)


install-rs: rs
	cp $(GRS)/vs.rs $(VS_DEST_RS_CLI)/mod.rs
	cp $(GRS)/vs.rs $(VS_DEST_RS_NODE)/mod.rs
	cp $(GRS)/vss.rs $(VSS_DEST_RS_NODE)/mod.rs


$(GGO)/vsapi: vs.thrift
	mkdir -p $(GGO)
	$(THRIFTCC) -r -out $(GGO) --gen go $<


$(GGO)/vssapi: vss.thrift
	mkdir -p $(GGO)
	$(THRIFTCC) -r -out $(GGO) --gen go $<


$(GRS)/vs.rs: vs.thrift
	mkdir -p $(GRS)
	$(THRIFTCC) -r -out $(GRS) --gen rs $<


$(GRS)/vss.rs: vss.thrift
	mkdir -p $(GRS)
	$(THRIFTCC) -r -out $(GRS) --gen rs $<


clean:
	rm -rf $(GGO) && rm -rf $(GRS)


.PHONY: all go rs install-go install-rs clean

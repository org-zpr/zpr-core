# Requires that env var $THRIFTCC is set to location of thrift compiler.

DEST_GO := ../core/pkg/vsapi
DEST_RS_CLI := ../cli/src/vsapi
DEST_RS_NODE := ../../node/src/vsapi

GGO := gen-go
GRS := gen-rs

SUMSFILE := md5sums.txt



ifndef THRIFTCC
  $(error must set THRIFTCC to location of thrift compiler)
endif


all: go rs


go: $(GGO)/vsapi


rs: $(GRS)/vsapi


install-go: sums go
	test -d $(DEST_GO) || mkdir $(DEST_GO)
	cp $(GGO)/vsapi/*.go $(DEST_GO)
	cp  $(SUMSFILE) $(DEST_GO)


install-rs: sums rs
	cp $(GRS)/vs.rs $(DEST_RS_CLI)/mod.rs
	cp $(SUMSFILE) $(DEST_RS_CLI)
	cp $(GRS)/vs.rs $(DEST_RS_NODE)/mod.rs
	cp $(SUMSFILE) $(DEST_RS_NODE)


$(GGO)/vsapi: vs.thrift
	mkdir -p $(GGO)
	$(THRIFTCC) -r --gen go $<


$(GRS)/vsapi: vs.thrift
	mkdir -p $(GRS)
	$(THRIFTCC) -r -out $(GRS) --gen rs $<


sums: vs.thrift
	md5sum $< >$(SUMSFILE)


clean:
	rm -rf $(GGO) && rm -rf $(GRS) && rm -f $(SUMSFILE)


.PHONY: all go rs install-go install-rs clean sums

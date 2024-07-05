# Requires that env var $THRIFTCC is set to location of thrift compiler.


DEST_GO := ../core/pkg/vsapi
DEST_RS_CLI := ../cli/src/vsapi
DEST_RS_NODE := ../../node/src/vsapi

GGO := gen-go
GRS := gen-rs



ifndef THRIFTCC
  $(error must set THRIFTCC to location of thrift compiler)
endif


all: go rs


go: $(GGO)/vsapi


rs: $(GRS)/vsapi


install-go: go
	test -d $(DEST_GO) || mkdir $(DEST_GO)
	cp $(GGO)/vsapi/*.go $(DEST_GO)


install-rs: rs
	cp $(GRS)/vs.rs $(DEST_RS_CLI)/mod.rs
	cp $(GRS)/vs.rs $(DEST_RS_NODE)/mod.rs


$(GGO)/vsapi: vs.thrift
	$(THRIFTCC) -r --gen go $<


$(GRS)/vsapi: vs.thrift
	mkdir -p $(GRS)
	$(THRIFTCC) -r -out $(GRS) --gen rs $<


clean:
	rm -rf $(GGO) && rm -rf $(GRS)


.PHONY: all go rs install-go install-rs clean

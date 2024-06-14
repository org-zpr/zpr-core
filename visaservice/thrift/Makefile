# Requires that env var $THRIFTCC is set to location of thrift compiler.


DEST_GO := ../core/pkg/vsapi

GGO := gen-go
GRS := gen-rs


all: go rs


go: $(GGO)/vsapi


rs: $(GRS)/vsapi


install-go: go
	test -d $(DEST_GO) || mkdir $(DEST_GO)
	cp $(GGO)/vsapi/*.go $(DEST_GO)


$(GGO)/vsapi: vs.thrift
	$(THRIFTCC) -r --gen go $<


$(GRS)/vsapi: vs.thrift
	mkdir -p $(GRS)
	$(THRIFTCC) -r -out $(GRS) --gen rs $<


clean:
	rm -rf $(GGO) && rm -rf $(GRS)


.PHONY: all go rs install-go clean

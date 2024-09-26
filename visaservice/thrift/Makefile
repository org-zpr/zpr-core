THRIFTCC=thrift

# VS_DEST_GO := ../core/pkg/vsapi
# VS_DEST_RS_CLI := ../cli/src/vsapi
# VS_DEST_RS_NODE := ../../node/src/vsapi


# Build output directories for the go and rust
BUILD_GO := gen-go
BUILD_RS := gen-rs




all: go rs

install: install-go install-rs

go: $(BUILD_GO)/vsapi

rs: $(BUILD_RS)/vs.rs

#install-go: sums go
#	test -d $(VS_DEST_GO)  || mkdir $(VS_DEST_GO)
#	cp $(BUILD_GO)/vsapi/*.go  $(VS_DEST_GO)
#	cp $(VS_SUM)               $(VS_DEST_GO)


#install-rs: sums rs
#	cp $(BUILD_RS)/vs.rs  $(VS_DEST_RS_CLI)/mod.rs
#	cp $(BUILD_RS)/vs.rs  $(VS_DEST_RS_NODE)/mod.rs
#	cp $(VS_SUM)          $(VS_DEST_RS_CLI)
#	cp $(VS_SUM)          $(VS_DEST_RS_NODE)


$(BUILD_GO)/vsapi: vs.thrift
	mkdir -p $(BUILD_GO)
	$(THRIFTCC) -r -out $(BUILD_GO) --gen go $<


$(BUILD_RS)/vs.rs: vs.thrift
	mkdir -p $(BUILD_RS)
	$(THRIFTCC) -r -out $(BUILD_RS) --gen rs $<


$(SUMS): %.thrift.sum: %.thrift
	md5sum $< >$@


clean:
	rm -rf $(BUILD_GO) && rm -rf $(BUILD_RS) 


.PHONY: all go rs install clean

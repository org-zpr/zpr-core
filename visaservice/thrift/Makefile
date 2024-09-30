THRIFTCC=thrift

# Build output directories for the go and rust
BUILD_GO := gen-go
BUILD_RS := gen-rs



$(BUILD_GO)/vsapi: vs.thrift
	mkdir -p $(BUILD_GO)
	$(THRIFTCC) -r -out $(BUILD_GO) --gen go $<


$(BUILD_RS)/vs.rs: vs.thrift
	mkdir -p $(BUILD_RS)
	$(THRIFTCC) -r -out $(BUILD_RS) --gen rs $<


$(SUMS): %.thrift.sum: %.thrift
	md5sum $< >$@


.PHONY: all go rs clean

all: go rs

go: $(BUILD_GO)/vsapi

rs: $(BUILD_RS)/vs.rs

clean:
	rm -rf $(BUILD_GO) && rm -rf $(BUILD_RS) 



.DEFAULT_GOAL := all

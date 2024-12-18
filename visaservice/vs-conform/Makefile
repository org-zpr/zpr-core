
OUT_DIR := build

pkg/vsapi: thrift-go


.PHONY: all build vstbin test clean dist-clean thrift-go

all: build

build: vstbin

vstbin: pkg/vsapi
	go build -o $(OUT_DIR)/vs-conform


thrift-go:
	$(MAKE) -C ../thrift go
	rm -rf pkg/vsapi && mkdir pkg/vsapi
	cp ../thrift/gen-go/vsapi/*.go pkg/vsapi


test:
	go test -short


clean:
	rm -rf $(OUT_DIR)

dist-clean: clean
	rm -rf pkg/vsapi


.DEFAULT_GOAL := all



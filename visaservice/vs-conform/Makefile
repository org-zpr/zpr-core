
OUT_DIR := build


.PHONY: all build vstbin test clean dist-clean

all: build

build: vstbin

vstbin:
	go build -o $(OUT_DIR)/vs-conform


test:
	go test -short


clean:
	rm -rf $(OUT_DIR)

dist-clean: clean


.DEFAULT_GOAL := all



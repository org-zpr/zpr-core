PROJECT_NAME := vs
PKG := "zpr.org/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

OUT_DIR := build
PKG_VSERVICE := $(PKG)/cmd/vservice
GFLAGS:=


ifneq ($(BUILD), release) 
	ifndef PATCH
		PATCH=`date -u +%Y%m%d%H%M%S`-dev
	endif
endif

# If $BUILD=release then strip binaries.
ifeq ($(BUILD), release)
	$(info *BUILD=release)
	GFLAGS := $(GFLAGS) -ldflags="-s -w -X main.BuildVersion=$(PATCH)"
else
	GFLAGS := $(GFLAGS) -ldflags="-X main.BuildVersion=$(PATCH)"
endif


all: check build


build: vservice


vservice:
	go build $(GFLAGS) -o $(OUT_DIR)/vservice -v $(PKG_VSERVICE)


test:
	go test -short ${PKG_LIST}


clean:
	rm -rf $(OUT_DIR)


# If check fails, the thrift files need to be rebuilt
check:
	cd ../thrift && md5sum -c ../core/pkg/vsapi/vs.thrift.sum


.PHONY: all build vservice test clean check

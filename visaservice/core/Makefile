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


.PHONY: all
all: build


.PHONY: build
build: vservice


.PHONY: vservice
vservice:
	go build $(GFLAGS) -o $(OUT_DIR)/vservice -v $(PKG_VSERVICE)


.PHONY: test
test:
	go test -short ${PKG_LIST}


.PHONY: clean
clean:
	rm -rf $(OUT_DIR)
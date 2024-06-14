PKG := "zpr.org/vsx/polio"
GFLAGS:=



# If $BUILD=release then strip binaries.
ifeq ($(BUILD), release)
	$(info *BUILD=release)
	GFLAGS := $(GFLAGS) -ldflags="-s -w"
endif


.PHONY: all
all: build


.PHONY: build
build:
	go build $(GFLAGS) $(PKG)/...


.PHONY: test
test:
	go test -short $(PKG)/...


.PHONY: protobuf
protobuf:
	$(MAKE) -f Makefile.pb all



OUT_DIR := build
PKG := cactl

.PHONY: all
all:build

.PHONY: build
build:
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/$(PKG) $(PKG)/*.go

.PHONY: test
test:
	echo "No tests to run yet."

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)


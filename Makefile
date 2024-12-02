

info:
	@echo 
	@echo Welcome to ZPR core
	@echo ===================
	@echo 
	@echo Build your own adventure:
	@echo "  make it-so       - build everything!"
	@echo "  make test        - run all unit tests!"
	@echo "  make it-gone     - clean everything!"
	@echo ""
	@echo "  make ph          - build the packet handler"
	@echo "  make libnode     - build the node library"
	@echo ""
	@echo "  make deps        - build the ancillary packages"
	@echo "  make diagrams    - build PlantUML diagrams"
	@echo 
	@echo \>_
	@echo


it-so: deps adapter ph-debug visaservice diagrams

it-gone:
	cd adapter/ph && cargo clean
	cd adapter/ph-debug && cargo clean
	cd cbpf-rs && cargo clean
	cd cslab && cargo clean
	$(MAKE) -C libnode dist-clean
	$(MAKE) -C visaservice/core dist-clean
	$(MAKE) -C visaservice clean
	$(MAKE) -C visaservice/thrift clean
	rm -rf diagrams/output


test:
	$(MAKE) -C adapter/ph test
	cd adapter/ph-debug && cargo test
	cd cbpf-rs && cargo test
	cd cslab && cargo test
	$(MAKE) -C libnode test
	$(MAKE) -C visaservice test



deps: cbpf cslab zpr-ext thrift


libnode:
	$(MAKE) -C libnode

ph: libnode
	$(MAKE) -C adapter/ph

ph-debug:
	cd adapter/ph-debug && cargo build

diagrams:
	$(MAKE) -C diagrams

cbpf: 
	cd cbpf-rs && cargo build

cslab:
	cd cslab && cargo build

zpr-ext:
	cd zpr-ext && cargo build

thrift:
	$(MAKE) -C visaservice/thrift

visaservice:
	$(MAKE) -C visaservice all


.PHONY: it-so it-gone test deps libnode ph ph-debug diagrams cbpf cslab zpr-ext thrift visaservice

.DEFAULT_GOAL := info

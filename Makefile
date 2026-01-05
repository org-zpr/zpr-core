

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


it-so: deps adapter ph ph-cli

it-gone:
	cd adapter/ph && cargo clean
	cd adapter/cli && cargo clean
	cd cbpf-rs && cargo clean
	cd cslab && cargo clean
	$(MAKE) -C libnode dist-clean
	rm -rf diagrams/output


test:
	$(MAKE) -C adapter/ph test
	cd adapter/cli && cargo test
	cd cbpf-rs && cargo test
	cd cslab && cargo test
	$(MAKE) -C libnode test



deps: cbpf cslab zpr-ext

libnode:
	$(MAKE) -C libnode

ph: libnode
	$(MAKE) -C adapter/ph

ph-cli:
	cd adapter/cli && cargo build

diagrams:
	$(MAKE) -C diagrams

cbpf: 
	cd cbpf-rs && cargo build

cslab:
	cd cslab && cargo build

zpr-ext:
	cd zpr-ext && cargo build

zpr-crate-related:
	$(MAKE) -C libnode
	$(MAKE) -C libnode2
	$(MAKE) -C adapter/ph


.PHONY: it-so it-gone test deps libnode ph ph-cli diagrams cbpf cslab zpr-ext zpr-crate-related

.DEFAULT_GOAL := info

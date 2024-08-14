

info:
	@echo 
	@echo Welcome to ZPR core
	@echo ===================
	@echo 
	@echo There are three exits here:
	@echo "  make node        - build the node"
	@echo "  make adapter     - build the adapter"
	@echo "  make nodeadapter - build the node and the adapter"
	@echo 
	@echo \>_
	@echo


# Build the node, cd, and cactl
nodeadapter: node adapter

node:
	$(MAKE) -C node all

adapter:
	$(MAKE) -C adapter/cactl all
	$(MAKE) -C adapter/cd all


.PHONY: nodeadapter node adapter


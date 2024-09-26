TOPTARGETS := all test

MODULES = polio snio zpl

clean:
	@echo "make mods/clean - NOP"

$(TOPTARGETS): $(MODULES)
$(MODULES):
	$(MAKE) -C $@ $(MAKECMDGOALS)




.PHONY: $(TOPTARGETS) $(MODULES)


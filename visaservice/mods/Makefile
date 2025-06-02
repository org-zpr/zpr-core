TOPTARGETS := all test

MODULES = polio snio

clean:
	@echo "make mods/clean - NOP"

$(TOPTARGETS): $(MODULES)
$(MODULES):
	$(MAKE) -C $@ $(MAKECMDGOALS)




.PHONY: $(TOPTARGETS) $(MODULES)


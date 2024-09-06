PLANTUML = plantuml

PLANTUML_OPTS = -noerror -failfast

OUTDIR = output

DIAGRAMS = \
	agent_input \
	agent_output \
	fastpath-overview \
	maybe_capture \
	substrate_egress \
	substrate_ingress

$(OUTDIR)/%.svg: %.puml
	$(PLANTUML) $(PLANTUML_OPTS) -tsvg -o$(dir $@) $< || $(PLANTUML) -ttxt -p < $<

$(OUTDIR)/%.png: %.puml
	$(PLANTUML) $(PLANTUML_OPTS) -tpng -o$(dir $@) $< || $(PLANTUML) -ttxt -p < $<

.PHONY: all-svg all-png

all-svg: $(addprefix $(OUTDIR)/,$(addsuffix .svg,$(DIAGRAMS)))
all-png: $(addprefix $(OUTDIR)/,$(addsuffix .png,$(DIAGRAMS)))

.DEFAULT_GOAL := all-svg

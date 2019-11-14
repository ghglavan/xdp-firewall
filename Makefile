# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SOURCES = $(wildcard source_*)
SOURCES_CLEAN = $(addsuffix _clean,$(SOURCES))

.PHONY: clean $(SOURCES) $(SOURCES_CLEAN)

all: $(SOURCES)
clean: $(SOURCES_CLEAN)

$(SOURCES):
	$(MAKE) -C $@

$(SOURCES_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean
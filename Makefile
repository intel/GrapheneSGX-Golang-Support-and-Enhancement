SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean format regression

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@

.PHONY: test
test:
	$(MAKE) -C Pal $@

.PHONY: install
install:
	@echo "\"make install\" is deprecated. use \"make\" instead."

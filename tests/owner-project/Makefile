# SPDX-License-Identifier: Apache-2.0
# An incremental project example, not a package transaction manager.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.PHONY: all check clean defaults stamps jobserver-check path-fallback

all: build/stats

build:
	mkdir -p "$@"

build/%.o: src/%.cpp flags.rsp | build
	$(CXX) @flags.rsp -MMD -MP -MF "$(@:.o=.d)" -c "$<" -o "$@"

build/libstats.a: build/parse.o build/summary.o
	@set -eu; tmp="$@.tmp.$$$$"; trap 'rm -f "$$tmp"' EXIT; \
	  $(AR) rcs "$$tmp" $^; $(RANLIB) "$$tmp"; mv "$$tmp" "$@"

build/stats: build/main.o build/libstats.a
	@set -eu; tmp="$@.tmp.$$$$"; trap 'rm -f "$$tmp"' EXIT; \
	  $(CXX) @flags.rsp $^ -o "$$tmp"; mv "$$tmp" "$@"

# GNU Make supplies CXX (c++ in Andrix), AR and the default shell. RANLIB is
# explicit here because it is not a GNU Make builtin on every host.
RANLIB = ranlib

check: all
	./build/stats 2 4 6

defaults:
	@echo CC=$(CC) CXX=$(CXX) AR=$(AR) SHELL=$(SHELL)

stamps:
	stat -c '%n:%Y' build/main.o build/parse.o build/summary.o build/stats

jobserver-check:
	+$(MAKE) --no-print-directory -f jobs.mk

path-fallback:
	+$(MAKE) --no-print-directory -f fallback.mk

clean:
	rm -rf build

-include $(wildcard build/*.d)

# SPDX-License-Identifier: Apache-2.0
# Exercise the child's absent-PATH fallback, without changing global environment.
unexport PATH
.PHONY: all
all:
	uname -m

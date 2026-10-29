# Copyright (c) 2026 haasanen — SPDX-License-Identifier: GPL-3.0-only
# splitscreen-unlock mod for mcpelauncher (mod_init ABI) + offline anchor verifier
CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17

all: splitscreen-unlock.so anchor-verify

splitscreen-unlock.so: splitscreen_unlock.cpp
	$(CXX) $(CXXFLAGS) -fPIC -shared -o $@ $<

anchor-verify: splitscreen_unlock.cpp
	$(CXX) $(CXXFLAGS) -DSTANDALONE -o $@ $< -ldl

clean:
	rm -f splitscreen-unlock.so anchor-verify

.PHONY: all clean

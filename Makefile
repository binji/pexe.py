# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# NACL_SDK_ROOT must be defined!

#
# Compute tool paths
#
PNACL_TC_PATH := $(abspath $(NACL_SDK_ROOT)/toolchain/linux_pnacl)
PNACL_CXX := $(PNACL_TC_PATH)/bin/pnacl-clang++
PNACL_FINALIZE := $(PNACL_TC_PATH)/bin/pnacl-finalize
CXXFLAGS := -I$(NACL_SDK_ROOT)/include
LDFLAGS := -L$(NACL_SDK_ROOT)/lib/pnacl/Release -lppapi_cpp -lppapi

.PHONY: all clean

# Declare the ALL target first, to make the 'all' target the default build
all: simple.pexe

clean:
	rm -rf *.bc *.pexe

simple.bc: simple.cc
	$(PNACL_CXX) -o $@ $< -O2 $(CXXFLAGS) $(LDFLAGS)

simple.pexe: simple.bc
	$(PNACL_FINALIZE) -o $@ $<


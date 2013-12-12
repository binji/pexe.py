# Copyright (c) 2013 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

VALID_TOOLCHAINS := pnacl
CONFIG := Release

# NACL_SDK_ROOT must be defined!
ifeq (,$(NACL_SDK_ROOT))
  $(error NACL_SDK_ROOT is not defined.)
endif
include $(NACL_SDK_ROOT)/tools/common.mk


LIBS = $(DEPS) ppapi pthread
CFLAGS = -Wall

TARGETS = fact simple hello_world
fact_SOURCES = fact.c
simple_SOURCES = simple.c
hello_world_SOURCES = hello_world.c

.PHONY: all
all: $(addsuffix .pexe,$(TARGETS))

define TARGET_RULE
$(1).pexe: pnacl/Release/$(1).pexe
	@cp $$< $$@

$$(foreach src,$$($(1)_SOURCES),$$(eval $$(call COMPILE_RULE,$$(src),$(CFLAGS))))
$$(eval $$(call LINK_RULE,$(1),$$($(1)_SOURCES),$(LIBS)))
endef

$(foreach target,$(TARGETS),$(eval $(call TARGET_RULE,$(target))))

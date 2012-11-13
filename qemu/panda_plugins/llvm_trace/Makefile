PLUGIN_NAME=llvm_trace

# Include the PANDA Makefile rules
include ../panda.mak

LLVM_BUILD_TYPE = $(shell ../../$(LLVMDIR)/bin/llvm-config --build-mode)

# Include files and lib from our LLVM project
CXXFLAGS+=$(LLVM_CXXFLAGS) -I../../../llvm-3.0/projects/laredo/include/ -I../../tcg
LIBS+=../../../llvm-3.0/projects/laredo/$(LLVM_BUILD_TYPE)/lib/libLaredoAnalysis.a

CFLAGS+=-O0 -g
CXXFLAGS+=-O0 -g

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CXX) $(QEMU_CXXFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
endif


PLUGIN_NAME=bitcode_callgraph

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME): \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(CXXFLAGS) \
            -o $@ $^ $(LIBS),"  PLUGIN_TEST  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)
endif


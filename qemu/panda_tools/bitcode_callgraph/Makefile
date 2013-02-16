TOOL_NAME=bitcode_callgraph

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

$(TOOL_TARGET_DIR)/$(TOOL_NAME): \
    $(TOOL_SRC_ROOT)/$(TOOL_NAME)/$(TOOL_NAME).cpp

	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(CXXFLAGS) \
            -o $@ $^ $(LIBS),"  PANDA_TOOL  $@")

ifdef CONFIG_LLVM
all: $(TOOL_TARGET_DIR)/$(TOOL_NAME)
endif


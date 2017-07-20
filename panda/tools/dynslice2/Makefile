TOOL_NAME=dynslice

CXXFLAGS += -std=c++11 -O3 -march=native

$(TOOL_TARGET_DIR)/$(TOOL_NAME): \
	$(TOOL_SRC_ROOT)/$(TOOL_NAME)/$(TOOL_NAME).cpp

	$(info libs is $(LIBS))
	$(info llvm cxx flags is $(LLVM_CXXFLAGS))
	$(info dollar^ is $^)
	$(info dollar@ is $@)
	$(call quiet-command,$(CXX) $(LLVM_CXXFLAGS) $(QEMU_INCLUDES) $(CXXFLAGS) \
	-o $@ $^ $(LIBS) -I/home/raywang/panda/panda/plugins/llvm_trace2/,"  PANDA_TOOL  $@")

ifdef CONFIG_LLVM
all: $(TOOL_TARGET_DIR)/$(TOOL_NAME)
endif

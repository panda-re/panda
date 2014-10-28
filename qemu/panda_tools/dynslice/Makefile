TOOL_NAME=dynslice

# Include the PANDA Makefile rules
include ../panda.mak

CXXFLAGS += -std=c++11

$(TOOL_TARGET_DIR)/$(TOOL_NAME): \
    $(TOOL_SRC_ROOT)/$(TOOL_NAME)/$(TOOL_NAME).cpp

	$(call quiet-command,$(CXX) $(LLVM_CXXFLAGS) -UNDEBUG $(QEMU_INCLUDES) $(CXXFLAGS) \
            -o $@ $^ $(LIBS),"  PANDA_TOOL  $@")

$(TOOL_TARGET_DIR)/logreverse_mmap: \
    $(TOOL_SRC_ROOT)/$(TOOL_NAME)/logreverse_mmap.cpp
	$(call quiet-command,$(CXX) $(CXXFLAGS) \
            -o $@ $^ ,"  PANDA_TOOL  $@")
	
ifdef CONFIG_LLVM
all: $(TOOL_TARGET_DIR)/$(TOOL_NAME) $(TOOL_TARGET_DIR)/logreverse_mmap
endif


PLUGIN_NAME=llvm_helpers

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

# plugin source file depends on shadow memory stuff in panda directory
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp \
    $(wildcard $(SRC_PATH)/panda/*.[ch]) $(wildcard $(SRC_PATH)/panda/*.cpp) 

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

	$(call quiet-command,$(CXX) $(QEMU_CXXFLAGS) -fPIC -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
endif


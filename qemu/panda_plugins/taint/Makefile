PLUGIN_NAME=taint

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

#CFLAGS+=-O0 -g
#CXXFLAGS+=-O0 -g

# plugin source file depends on shadow memory stuff in panda directory
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp \
    $(wildcard $(SRC_PATH)/panda/*.[ch]) $(wildcard $(SRC_PATH)/panda/*.cpp) 

# plugin source file depends on shadow memory stuff in panda directory
$(PLUGIN_TARGET_DIR)/llvm_taint_lib.o: \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.cpp \
    $(wildcard $(SRC_PATH)/panda/*.[ch]) \
    $(wildcard $(SRC_PATH)/panda/*.cpp)

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o \
    $(PLUGIN_TARGET_DIR)/llvm_taint_lib.o

	$(call quiet-command,$(CXX) $(CXXFLAGS) $(QEMU_CXXFLAGS) \
            -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
endif


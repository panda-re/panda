PLUGIN_NAME=taint

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

# plugin source file depends on shadow memory stuff in panda directory
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp \
    $(wildcard $(SRC_PATH)/panda/*.[ch]) $(wildcard $(SRC_PATH)/panda/*.cpp) \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.[cpp|h])


$(PLUGIN_TARGET_DIR)/panda_dynval_inst.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/panda_dynval_inst.[cpp|h]) \




# plugin source file depends on shadow memory stuff in panda directory
$(PLUGIN_TARGET_DIR)/llvm_taint_lib.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.[cpp|h]) \
    $(wildcard $(SRC_PATH)/panda/*.[ch]) \
    $(wildcard $(SRC_PATH)/panda/*.cpp)






# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_TARGET_DIR)/my_mem.o \
    $(PLUGIN_TARGET_DIR)/bitvector_label_set.o \
    $(PLUGIN_TARGET_DIR)/shad_dir_32.o \
    $(PLUGIN_TARGET_DIR)/shad_dir_64.o \
    $(PLUGIN_TARGET_DIR)/taint_processor.o \
    $(PLUGIN_TARGET_DIR)/panda_stats.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o \
    $(PLUGIN_TARGET_DIR)/llvm_taint_lib.o 

	$(call quiet-command,$(CXX) $(CXXFLAGS) $(QEMU_CXXFLAGS) \
            -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
endif


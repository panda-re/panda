PLUGIN_NAME=taint

# Include the PANDA Makefile rules
include ../panda.mak

QEMU_CFLAGS+=-std=c++11


# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

QEMU_CXXFLAGS+= -std=c++11
# Since std::vector<bool> uses less compute and less memory, it's the default now
# Comment this out and leave the next entry commented to enable std::set<uint32_t> labelset implementation
QEMU_CXXFLAGS+= -DLABELSET_VECTOR
#uncomment to enable std::bitset labelset implementation. Change the set size if needed!
#QEMU_CXXFLAGS+= -DLABELSET_STDBITSET 
#QEMU_CXXFLAGS+= -DLABELSET_MAX_LABELS=256
QEMU_CXXFLAGS+= -Wno-unused-variable

$(PLUGIN_TARGET_DIR)/my_mem.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/my_mem.[cpp|h])

$(PLUGIN_TARGET_DIR)/bitvector_label_set.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h) \
    $(wildcard $(SRC_PATH)/panda/*.h) \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/sparsebitset.cpp

$(wildcard $(PLUGIN_TARGET_DIR)/shad_dir_*.o): \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h) \
    $(wildcard $(SRC_PATH)/panda/*.h) \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/bitvector_label_set.cpp

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp \
    $(wildcard $(PLUGIN_SRC_ROOT)/panda/*.[ch]) $(wildcard $(SRC_PATH)/panda/*.cpp) \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.[cpp|h]) \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.[ch]) \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.cpp)

$(PLUGIN_TARGET_DIR)/taint_processor.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h) \
    $(wildcard $(SRC_PATH)/panda/*.h)

$(PLUGIN_TARGET_DIR)/llvm_taint_lib.o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.[cpp|h]) \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.[cpp|h]) \
    $(wildcard $(SRC_PATH)/panda/*.[cpp|h])


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


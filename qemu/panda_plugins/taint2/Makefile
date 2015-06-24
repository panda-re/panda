PLUGIN_NAME=taint2

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+= $(LLVM_CXXFLAGS) -I$(SRC_PATH)/panda_tools/pirate_utils/linux

DBGFLAGS=
DBGFLAGS+= #-DTAINTDEBUG

QEMU_CFLAGS+= $(DBGFLAGS)
QEMU_CXXFLAGS+= $(DBGFLAGS)

QEMU_CXXFLAGS+= -std=c++11 -Wno-type-limits

TAINT_OP_CFLAGS= -O3 -std=c11 -Wno-typedef-redefinition -fno-stack-protector -fno-omit-frame-pointer -Wno-type-limits $(CLANG_CXXFLAGS)

# This will make things easier.
$(PLUGIN_OBJ_DIR)/%.o: $(wildcard *.h) $(wildcard $(SRC_PATH)/panda/*.h)

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_taint2.so: \
    $(PLUGIN_OBJ_DIR)/shad_dir_32.o \
    $(PLUGIN_OBJ_DIR)/shad_dir_64.o \
    $(PLUGIN_OBJ_DIR)/llvm_taint_lib.o \
    $(PLUGIN_OBJ_DIR)/fast_shad.o \
    $(PLUGIN_OBJ_DIR)/taint_ops.o \
    $(PLUGIN_OBJ_DIR)/label_set.o \
    $(PLUGIN_OBJ_DIR)/taint_processor.o \
    $(PLUGIN_OBJ_DIR)/taint2.o

	$(call quiet-command,$(CXX) $(CXXFLAGS) $(QEMU_CXXFLAGS) \
            -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

$(PLUGIN_OBJ_DIR)/llvm_%.bc: %.cpp $(wildcard *.h)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,\
		$(filter-out -g -Wold-style-declaration -std=c11,\
			$(LLVMCC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) \
			$(QEMU_DGFLAGS) $(CXXFLAGS) $(TAINT_OP_CFLAGS) \
			-emit-llvm -c -o $@ $<),"  LLVM    $@")

$(PLUGIN_TARGET_DIR)/panda_taint2_ops.bc: $(PLUGIN_OBJ_DIR)/llvm_taint_ops.bc
	$(call quiet-command, $(LLVM_LINK) -o $@ $^,"  LLVM_LINK $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_taint2.so \
	$(PLUGIN_TARGET_DIR)/panda_taint2_ops.bc
endif


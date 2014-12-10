PLUGIN_NAME=taint2

# Include the PANDA Makefile rules
include ../panda.mak

# Include files and lib from LLVM
CXXFLAGS+= $(LLVM_CXXFLAGS)

DBGFLAGS=
DBGFLAGS+= -DTAINT2_NOINLINE #-DTAINTDEBUG

QEMU_CFLAGS+= $(DBGFLAGS)
QEMU_CXXFLAGS+= $(DBGFLAGS)

QEMU_CXXFLAGS+= -std=c++11

TAINT_OP_CFLAGS= -O3 -std=c11 -Wno-typedef-redefinition -fno-stack-protector -fno-omit-frame-pointer
LLVM_OPS=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/taint2_taint_ops.c
MY_MEM=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/taint2_my_mem.cpp

# This will make things easier.
$(wildcard $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_*.o): \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h)

$(wildcard $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_shad_dir_*.o): \
    $(wildcard $(SRC_PATH)/panda/*.h)

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
    $(wildcard $(PLUGIN_SRC_ROOT)/panda/*.h) \

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_llvm_taint_lib.o: \
    $(SRC_PATH)/panda/guestarch.h \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/llvm_taint_lib.h \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/my_mem.h \
    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).h

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_my_mem.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_shad_dir_32.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_shad_dir_64.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_llvm_taint_lib.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_fast_shad.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_taint_ops.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_taint_processor.o \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

	$(call quiet-command,$(CXX) $(CXXFLAGS) $(QEMU_CXXFLAGS) \
            -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_%.bc: \
	$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME)_%.c \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h)

	$(call quiet-command,\
		$(filter-out -g -Wold-style-declaration,\
			$(LLVMCC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) $(TAINT_OP_CFLAGS) \
			-emit-llvm -c -o $@ $<),"  LLVM    $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_%.bc: \
	$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME)_%.cpp \
    $(wildcard $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/*.h)

	$(call quiet-command,\
		$(filter-out -g -Wold-style-declaration -std=c11,\
			$(LLVMCC) $(QEMU_INCLUDES) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $(CXXFLAGS) $(TAINT_OP_CFLAGS) \
			-emit-llvm -c -o $@ $<),"  LLVM    $@")

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_ops.bc: \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_my_mem.bc \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_taint_ops.bc

	$(call quiet-command,\
		$(filter-out -g -Wold-style-declaration,\
			$(LLVM_LINK) -o $@ $^),"  LLVM_LINK $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so \
	$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_ops.bc
endif


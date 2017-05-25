# Include files and lib from LLVM
QEMU_CXXFLAGS+= $(LLVM_CXXFLAGS)

DBGFLAGS=
DBGFLAGS+= #-DTAINTDEBUG

QEMU_CFLAGS+= $(DBGFLAGS)
QEMU_CXXFLAGS+= $(DBGFLAGS)

QEMU_CXXFLAGS+= -Wno-type-limits -Wno-cast-qual

TAINT_OP_CFLAGS = -O3 -std=c11 -Wno-typedef-redefinition -fno-stack-protector
TAINT_OP_CFLAGS+= -fno-omit-frame-pointer -Wno-type-limits -stdlib=libc++ -x c++
TAINT_OP_CFLAGS+= $(CLANG_CXXFLAGS) $(DBGFLAGS)

TAINT_OP_FILTER = -g -Wold-style-declaration -std=c11 -fpermissive
TAINT_OP_FILTER+= -fstack-protector-strong -Wno-error=cpp -mcx16
TAINT_OP_FILTER+= -Wno-shift-negative-value


$(PLUGIN_TARGET_DIR)/panda_taint2.so: \
    $(PLUGIN_OBJ_DIR)/shad_dir_32.o \
    $(PLUGIN_OBJ_DIR)/shad_dir_64.o \
    $(PLUGIN_OBJ_DIR)/llvm_taint_lib.o \
    $(PLUGIN_OBJ_DIR)/fast_shad.o \
    $(PLUGIN_OBJ_DIR)/taint_ops.o \
    $(PLUGIN_OBJ_DIR)/label_set.o \
    $(PLUGIN_OBJ_DIR)/taint2.o \
    $(PLUGIN_OBJ_DIR)/taint_api.o

%_llvm.bc: %.cpp $(wildcard *.h)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,\
		$(filter-out $(TAINT_OP_FILTER),\
			$(LLVMCXX) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) \
			$(QEMU_DGFLAGS) $(CXXFLAGS) $(TAINT_OP_CFLAGS) \
			-emit-llvm -c -o $@ $<),"CLANGXX $(TARGET_DIR)$@")

$(PLUGIN_TARGET_DIR)/panda_taint2_ops.bc: $(PLUGIN_OBJ_DIR)/taint_ops_llvm.bc
	$(call quiet-command, $(LLVM_LINK) -o $@ $^,"LLVMLD  $(TARGET_DIR)$@")

all: $(PLUGIN_TARGET_DIR)/panda_taint2_ops.bc

# PANDA taint2 plugin
#
# Influential flags:
# 	-DTAINT2_DEBUG enables debug output.
# 	-DTAINT2_HYPERCALLS enables taint-related PANDA hypercalls, as used by LAVA
#
TAINT2_FLAGS   += -DTAINT2_HYPERCALLS

### Flags setup #####################################################
QEMU_CXXFLAGS += $(LLVM_CXXFLAGS) -Wno-type-limits -Wno-cast-qual $(TAINT2_FLAGS)
QEMU_CFLAGS   += $(TAINT2_FLAGS)

TAINT_OP_CFLAGS  = -O3 -std=c11 -Wno-typedef-redefinition -fno-stack-protector
TAINT_OP_CFLAGS += -fno-omit-frame-pointer -Wno-type-limits -stdlib=libc++ -x c++
TAINT_OP_CFLAGS += $(CLANG_CXXFLAGS) $(TAINT2_FLAGS)

TAINT_OP_FILTER = -g -Wold-style-declaration -std=c11 -fpermissive
TAINT_OP_FILTER+= -fstack-protector-strong -Wno-error=cpp -mcx16
TAINT_OP_FILTER+= -Wno-shift-negative-value

### Files setup #####################################################
TAINT2_SRC  = $(notdir $(wildcard $(PLUGIN_SRC_DIR)/*.cpp))
TAINT2_SRC := $(filter-out my_mem.cpp,$(TAINT2_SRC))
TAINT2_OBJ  = $(patsubst %.cpp,$(PLUGIN_OBJ_DIR)/%.o,$(TAINT2_SRC))

### Rules and recipes ###############################################

$(PLUGIN_OBJ_DIR)/update_cb_switch:
	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(QEMU_CXXFLAGS) \
		$(PLUGIN_SRC_DIR)/tests/update_cb_switch/update_cb_switch.cpp \
		-o $@ $(LIBS),"CXX $@")

$(PLUGIN_TARGET_DIR)/panda_taint2.so: $(TAINT2_OBJ)

all: $(PLUGIN_OBJ_DIR)/update_cb_switch



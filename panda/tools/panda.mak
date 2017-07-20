
include ../config-host.mak
include config-devices.mak
include config-target.mak
include $(SRC_PATH)/rules.mak


TOOL_TARGET_DIR=panda/tools
TOOL_SRC_ROOT=panda/tools

TOOL_SRC_DIR=$(TOOL_SRC_ROOT)/$(TOOL_NAME)

$(info tool_src_root is $(TOOL_SRC_ROOT))

TARGET_PATH=$(SRC_PATH)/target/$(TARGET_BASE_ARCH)
TARGET_BUILD=../target/$(TARGET_BASE_ARCH)

QEMU_CFLAGS+=-DNEED_CPU_H -fPIC
QEMU_CXXFLAGS+=-DNEED_CPU_H -fPIC

QEMU_CXXFLAGS+=-fpermissive -std=c++11

# These are all includes. I think.
QEMU_CFLAGS+=$(GLIB_CFLAGS)
QEMU_CXXFLAGS+=$(GLIB_CFLAGS) -Wno-pointer-arith

QEMU_INCLUDES+=-I$(TOOL_SRC_DIR) -I$(TOOL_SRC_ROOT) -I$(SRC_PATH)/panda/tools
QEMU_INCLUDES+=-I$(TOOL_TARGET_DIR) -I.. -I$(TARGET_PATH) -I$(TARGET_BUILD)

# These should get generated automatically and include dependency information.
#-include $(wildcard $(TOOL_OBJ_DIR)/*.d)

# You can override this recipe by using the full name of the tool in a
# tool Makefile. (e.g. $(TOOL_TARGET_DIR)/panda_$(TOOL_NAME).so).
#$(TOOL_TARGET_DIR)/panda_%.so:
	#$(call quiet-command,$(CXX) $(QEMU_CFLAGS) $(LDFLAGS) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS),"TOOL  $(TARGET_DIR)$@")

#all: $(TOOL_TARGET_DIR)/panda_$(TOOL_NAME).so
$(TOOL_TARGET_DIR)/%.o: %.c
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) -c -o $@ $<,"  CC    $@")

$(TOOL_TARGET_DIR)/%.o: %.cpp $(GENERATED_HEADERS)
	$(call quiet-command,$(CXX) $(filter-out -Wnested-externs -Wmissing-prototypes -Wstrict-prototypes -Wold-style-declaration -Wold-style-definition, $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $(CXXFLAGS)) -c -o $@ $<,"  CXX   $@")

#all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

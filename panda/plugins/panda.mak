# Note: We will be run from target directory. (build/target)

include ../config-host.mak
include config-devices.mak
include config-target.mak
include $(SRC_PATH)/rules.mak

PLUGIN_TARGET_DIR=panda/plugins
PLUGIN_OBJ_DIR=panda/plugins/$(PLUGIN_NAME)

PLUGIN_SRC_ROOT=$(SRC_PATH)/panda/plugins
PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)

TARGET_PATH=$(SRC_PATH)/target-$(TARGET_BASE_ARCH)

QEMU_CFLAGS+=-DNEED_CPU_H -fPIC
QEMU_CXXFLAGS+=-DNEED_CPU_H -fPIC

QEMU_CXXFLAGS+=-fpermissive -std=c++11
ifdef TARGET_ARM
QEMU_CXXFLAGS+=-Wno-error
endif

# These are all includes. I think.
QEMU_CFLAGS+=$(GLIB_CFLAGS)
QEMU_CXXFLAGS+=$(GLIB_CFLAGS)

QEMU_INCLUDES+=-I$(BUILD_DIR)/$(TARGET_DIR) -I$(BUILD_DIR)
QEMU_INCLUDES+=-I$(PLUGIN_SRC_DIR) -I. -I$(TARGET_PATH)
QEMU_INCLUDES+=-I$(SRC_PATH)/panda/include

$(PLUGIN_OBJ_DIR)/%.o: $(PLUGIN_SRC_DIR)/%.c
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) $($@-cflags) -c -o $@ $<,"  CC    $(TARGET_DIR)$@")

$(PLUGIN_OBJ_DIR)/%.o: $(PLUGIN_SRC_DIR)/%.cc
	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $($@-cflags) -c -o $@ $<,"  CXX   $(TARGET_DIR)$@")

$(PLUGIN_OBJ_DIR)/%.o: $(PLUGIN_SRC_DIR)/%.cpp
	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $($@-cflags) -c -o $@ $<,"  CXX   $(TARGET_DIR)$@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

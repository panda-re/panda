include ../../config-host.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-devices.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-target.mak
include $(SRC_PATH)/rules.mak
#ifneq ($(HWDIR),)
#include $(HWDIR)/config.mak
#endif

PLUGIN_TARGET_DIR=$(SRC_PATH)$(TARGET_DIR)panda_plugins

PLUGIN_SRC_ROOT=$(SRC_PATH)/panda_plugins

ifdef CONFIG_LINUX_USER

$(call set-vpath, $(SRC_PATH)/linux-user:$(SRC_PATH)/linux-user/$(TARGET_ABI_DIR))
QEMU_CFLAGS+=-I$(SRC_PATH)/linux-user/$(TARGET_ABI_DIR) -I$(SRC_PATH)/linux-user

endif

TARGET_PATH=$(SRC_PATH)/target-$(TARGET_BASE_ARCH)
QEMU_CFLAGS+=-I$(SRC_PATH)/$(TARGET_DIR) -I$(TARGET_PATH) -DNEED_CPU_H -fPIC
QEMU_CFLAGS+=$(GLIB_CFLAGS)

# flags valid for c but not for c++
CXXFLAGS_EXCLUDE=-Wnested-externs -Wmissing-prototypes -Wstrict-prototypes -Wold-style-declaration -Wold-style-definition

$(PLUGIN_TARGET_DIR)/%.o: %.c
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) -c -o $@ $<,"  CC    $@")

$(PLUGIN_TARGET_DIR)/%.o: %.cpp $(GENERATED_HEADERS)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $(CXXFLAGS)) -c -o $@ $<,"  CXX   $@")


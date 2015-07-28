# XXX You will need to change this!
# Tell it where to find panda
SRC_PATH=/home/you/git/panda/qemu

include $(SRC_PATH)/config-host.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-devices.mak
include $(SRC_PATH)/$(TARGET_DIR)/config-target.mak
include $(SRC_PATH)/rules.mak
#ifneq ($(HWDIR),)
#include $(HWDIR)/config.mak
#endif

PLUGIN_TARGET_DIR=$(SRC_PATH)$(TARGET_DIR)panda_plugins

PLUGIN_SRC_ROOT=$(EXTRA_PLUGINS_PATH)/panda_plugins
PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)


TARGET_PATH=$(SRC_PATH)/target-$(TARGET_BASE_ARCH)
QEMU_CFLAGS+=-I$(SRC_PATH)/$(TARGET_DIR) -I$(TARGET_PATH) -DNEED_CPU_H -fPIC
QEMU_CFLAGS+=$(GLIB_CFLAGS)

PLUGIN_OBJ_DIR=$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)

$(PLUGIN_OBJ_DIR):
	@[ -d  $@ ] || mkdir -p $@

$(PLUGIN_OBJ_DIR)/%.o: %.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) -c -o $@ $<,"  CC    $@")

$(PLUGIN_OBJ_DIR)/%.o: %.cpp $(GENERATED_HEADERS)
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CXX) $(filter-out -Wnested-externs -Wmissing-prototypes -Wstrict-prototypes -Wold-style-declaration -Wold-style-definition, $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $(CXXFLAGS)) -c -o $@ $<,"  CXX   $@")

$(PLUGIN_TARGET_DIR)/%.o: %.c
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_DGFLAGS) $(CFLAGS) -c -o $@ $<,"  CC    $@")

$(PLUGIN_TARGET_DIR)/%.o: %.cpp $(GENERATED_HEADERS)
	$(call quiet-command,$(CXX) $(filter-out -Wnested-externs -Wmissing-prototypes -Wstrict-prototypes -Wold-style-declaration -Wold-style-definition, $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(QEMU_DGFLAGS) $(CXXFLAGS)) -c -o $@ $<,"  CXX   $@")


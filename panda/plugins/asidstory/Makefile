# Don't forget to add your plugin to config.panda!

# Include the PANDA Makefile rules
include $(SRC_PATH)/panda/plugins/panda.mak

QEMU_CFLAGS+=-std=c++11

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+=-lm
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS),"  PLUG  $(TARGET_DIR)$@")

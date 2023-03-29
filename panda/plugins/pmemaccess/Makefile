# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=pmemaccess

# Include the PANDA Makefile rules
#include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
#$(PLUGIN_SRC_DIR)/memory-access.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/memory-access.c

$(PLUGIN_SRC_DIR)/pmemaccess.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).c

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_SRC_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")
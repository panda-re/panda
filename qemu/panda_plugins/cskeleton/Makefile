# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

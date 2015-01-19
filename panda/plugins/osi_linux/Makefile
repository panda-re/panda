# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=osi_linux

PLUGIN_OBJ_DIR=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)

PLUGIN_OBJ_FILES=$(PLUGIN_OBJ_DIR)/kernelinfo_read.o

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

$(PLUGIN_OBJ_DIR)/kernelinfo_read.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/utils/kernelinfo/kernelinfo_read.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) -c -o $@ $^,"  PLUGINOBJ CC $@")

# The main rule for your plugin. Please stick with the panda_ naming convention.
$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o $(PLUGIN_OBJ_FILES)
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

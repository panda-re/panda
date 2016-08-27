# Don't forget to add your plugin to config.panda!

PLUGIN_OBJ_FILES=$(PLUGIN_OBJ_DIR)/kernelinfo_read.o

# Include the PANDA Makefile rules
include $(SRC_PATH)/panda/plugins/panda.mak

# Influential plugin-specific flags.
# Include threads when listing all processes.
#QEMU_CFLAGS += -DOSI_LINUX_LIST_THREADS
# Enable test mode. See osi_linux.cpp:vmi_pgd_changed().
#QEMU_CFLAGS += -DOSI_LINUX_TEST

.PHONY: all

$(PLUGIN_OBJ_DIR)/kernelinfo_read.o: $(PLUGIN_SRC_DIR)/utils/kernelinfo/kernelinfo_read.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) -c -o $@ $^,"  UTLCC $(TARGET_DIR)$@")

# The main rule for your plugin. Please stick with the panda_ naming convention.

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o $(PLUGIN_OBJ_FILES)
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUG  $(TARGET_DIR)$@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

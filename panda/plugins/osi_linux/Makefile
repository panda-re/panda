# Don't forget to add your plugin to config.panda!

PLUGIN_OBJ_FILES=$(PLUGIN_OBJ_DIR)/kernelinfo_read.o

# Influential plugin-specific flags.
# Include threads when listing all processes.
#QEMU_CFLAGS += -DOSI_LINUX_LIST_THREADS
# Enable test mode. See osi_linux.cpp:asid_changed().
#QEMU_CFLAGS += -DOSI_LINUX_TEST

$(PLUGIN_OBJ_DIR)/kernelinfo_read.o: $(PLUGIN_SRC_DIR)/utils/kernelinfo/kernelinfo_read.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(QEMU_INCLUDES) $(QEMU_CFLAGS) -c -o $@ $^,"UTIL CC $(TARGET_DIR)$@")

# We could implement a better search strategy here. Oh well!
$(PLUGIN_OBJ_DIR)/kernelinfo.conf: $(PLUGIN_SRC_DIR)/kernelinfo.conf
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$@")

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
	$(PLUGIN_OBJ_FILES)

all: $(PLUGIN_OBJ_DIR)/kernelinfo.conf

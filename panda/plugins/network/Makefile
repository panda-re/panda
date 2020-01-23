# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
QEMU_INCLUDES += -I/usr/local/include
QEMU_INCLUDES += -I/usr/local/include/wireshark
QEMU_INCLUDES += -I/usr/local/include/wireshark/wiretap
LIBS += -lwiretap

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

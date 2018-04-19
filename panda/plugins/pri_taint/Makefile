QEMU_CXXFLAGS := $(filter-out -Wundef,$(QEMU_CXXFLAGS))
QEMU_CXXFLAGS += -DTAINT2_HYPERCALLS
QEMU_CFLAGS   += -DTAINT2_HYPERCALLS

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

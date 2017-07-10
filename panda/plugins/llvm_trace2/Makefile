# Don't forget to add your plugin to config.panda!

QEMU_CXXFLAGS+= $(LLVM_CXXFLAGS)
# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

QEMU_CXXFLAGS+= -Wno-type-limits -Wno-cast-qual

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

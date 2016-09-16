# Don't forget to add your plugin to config.panda!

# Include the PANDA Makefile rules
include $(SRC_PATH)/panda/plugins/panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# -DUSE_STACK_HEURISTIC tries to detect thread switches by sudden
# jumps in the stack pointer
LIBS+=-ldistorm3

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# -DUSE_STACK_HEURISTIC tries to detect thread switches by sudden
# jumps in the stack pointer
LIBS+=-lcapstone

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

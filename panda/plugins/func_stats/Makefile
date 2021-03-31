# Don't forget to add your plugin to config.panda

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CXXFLAGS+= $(LLVM_CXXFLAGS) -Wno-type-limits -Wno-cast-qual
# For func_stats CFLAGS is empty.
#CFLAGS+= -I/home/vigliag/software/llvm3/llvm/include -g
LIBS+=

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

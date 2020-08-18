# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=


PLUGIN_OBJFILES = \
	$(PLUGIN_OBJ_DIR)/hooks2.o

$(info $(PLUGIN_TARGET_DIR))
$(info $(PLUGIN_NAME))
$(info $(PLUGIN_OBJFILES))

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)

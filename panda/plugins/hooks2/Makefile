# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

ifeq ($(filter $(TARGET_ARM) $(TARGET_I386) $(TARGET_X86_64),y),)
PLUGIN_OBJFILES = $(PLUGIN_OBJ_DIR)/hooks2_stub.o
else
PLUGIN_OBJFILES = $(PLUGIN_OBJ_DIR)/hooks2.o
endif

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)

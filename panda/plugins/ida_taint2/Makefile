# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

$(PLUGIN_OBJ_DIR)/ida_taint2.py: $(PLUGIN_SRC_DIR)/ida_taint2.py
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$@")

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

all: $(PLUGIN_OBJ_DIR)/ida_taint2.py

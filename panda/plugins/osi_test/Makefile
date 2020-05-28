# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=
#
$(PLUGIN_OBJ_DIR)/osi_test_normalize.py: $(PLUGIN_SRC_DIR)/osi_test_normalize.py
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$@")

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

all: $(PLUGIN_OBJ_DIR)/osi_test_normalize.py

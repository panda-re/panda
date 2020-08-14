# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# use full path to target file so do not get circular dependency
# TARGET_DIR ends with /, so do not need explicit one
$(BUILD_DIR)/$(TARGET_DIR)$(PLUGIN_OBJ_DIR)/moviecounter.sh: $(PLUGIN_SRC_DIR)/moviecounter.sh
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$(PLUGIN_OBJ_DIR)/moviecounter.sh")

$(BUILD_DIR)/$(TARGET_DIR)$(PLUGIN_OBJ_DIR)/movie.sh: $(PLUGIN_SRC_DIR)/movie.sh
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$(PLUGIN_OBJ_DIR)/movie.sh")
	
# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

all: $(BUILD_DIR)/$(TARGET_DIR)$(PLUGIN_OBJ_DIR)/movie.sh $(BUILD_DIR)/$(TARGET_DIR)$(PLUGIN_OBJ_DIR)/moviecounter.sh

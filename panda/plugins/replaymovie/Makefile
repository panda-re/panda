# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

$(PLUGIN_TARGET_DIR)/moviecounter.sh: $(PLUGIN_OBJ_DIR)/moviecounter.sh
	$(call quiet-command,cp $< $@,"CP      $(PLUGIN_TARGET_DIR)$@")

$(PLUGIN_TARGET_DIR)/movie2.sh: $(PLUGIN_OBJ_DIR)/movie.sh
	$(call quiet-command,cp $< $@,"CP      $(PLUGIN_TARGET_DIR)$@")

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

all: $(PLUGIN_TARGET_DIR)/movie2.sh $(PLUGIN_TARGET_DIR)/moviecounter.sh

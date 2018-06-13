# Don't forget to add your plugin to config.panda!

# The main rule for your plugin. List all object-file dependencies.
O_FILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o 

.PHONY: all

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF): $(O_FILES)

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF)


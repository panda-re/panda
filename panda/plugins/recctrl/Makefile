# location of core plugin directory
PANDA_CORE_PLUGINS  ?=  $(SRC_PATH)/panda/plugins

ifeq ($(realpath $(PANDA_CORE_PLUGINS)),)
$(error Could not find PANDA core plugins directory in $(PANDA_CORE_PLUGINS))
endif

UTILS_HEADER = $(PLUGIN_SRC_DIR)/utils/$(PLUGIN_NAME).h

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o | \
	$(UTILS_HEADER)

$(UTILS_HEADER): $(PLUGIN_SRC_DIR)/$(PLUGIN_NAME).h
	cp -f $(<) $(@)

# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

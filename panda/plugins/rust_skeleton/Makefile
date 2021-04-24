# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=

# Example: this plugin has runtime symbol dependencies on plugin_x:
# LIBS+=-L$(PLUGIN_TARGET_DIR) -l:panda_plugin_x.so
# Also create a plugin_plugin.d file in this directory to ensure plugin_x
# gets compiled before this plugin, example contents:
# plugin-this_plugins_name : plugin-plugin_x
# or if you're using the extra plugins dir:
# extra-plugin-this_plugins_name : extra-plugin-plugin_x

# The main rule for your plugin. List all object-file dependencies.
PLUGIN_DIR = $(realpath $(join $(PANDA_PATH), /../panda/plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)


$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so : $(RUST_SOURCE)
	echo "PLUGIN_DIR" $(PLUGIN_DIR)
	echo "RUST_SOURCE" $(RUST_SOURCE)
	ls -la
	cargo build --manifest-path=$(PLUGIN_DIR)/Cargo.toml --target-dir=$(PLUGIN_DIR)
	cp -p $(PLUGIN_DIR)/target/debug/lib$(PLUGIN_NAME).so $@

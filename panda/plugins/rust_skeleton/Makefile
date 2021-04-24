# Don't forget to add your plugin to config.panda!

# Build rust plugins with make!

# The main rule for your plugin. List all object-file dependencies.
PLUGIN_DIR = $(realpath $(join $(PANDA_PATH), /../panda/plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)


$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so : $(RUST_SOURCE)
	echo "PLUGIN_DIR" $(PLUGIN_DIR)
	echo "RUST_SOURCE" $(RUST_SOURCE)
	ls -la
	cargo build --manifest-path=$(PLUGIN_DIR)/Cargo.toml --target-dir=$(PLUGIN_DIR)
	cp -p $(PLUGIN_DIR)/target/debug/lib$(PLUGIN_NAME).so $@

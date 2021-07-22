# Don't forget to add your plugin to config.panda!

# Build rust plugins with make!

# The main rule for your plugin. List all object-file dependencies.
PLUGIN_DIR = $(realpath $(join $(PANDA_PATH), /../panda/plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so : $(RUST_SOURCE) $(PLUGIN_DIR)/Cargo.toml
	@echo "CARGO   $(PLUGIN_DIR)"
	@cargo build --release --no-default-features --features=$(TARGET_NAME) \
		--manifest-path=$(PLUGIN_DIR)/Cargo.toml --target-dir=$(PLUGIN_DIR)/target
	@cp -p $(PLUGIN_DIR)/target/release/lib$(PLUGIN_NAME).so $@

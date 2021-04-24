# Build Rust projects with make!

PLUGIN_DIR = $(realpath $(join $(PANDA_PATH), /../panda/plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)


$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so : $(RUST_SOURCE)
	cargo build --manifest-path=$(PLUGIN_DIR)/Cargo.toml --target-dir=$(PLUGIN_DIR)
	cp -p $(PLUGIN_DIR)/target/debug/lib$(PLUGIN_NAME).so $@

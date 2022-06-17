# Remember to:
# * Add your plugin name to config.panda
# * Keep your plugin name the same as the folder name and Cargo.toml package name

# Output build artifacts to the build directory
PLUGIN_ARTIFACTS_DIR = $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/target

# recompile if any of the src/*.rs files changed, or Cargo.toml
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)
PLUGIN_DEPS=$(RUST_SOURCE) $(PLUGIN_DIR)/Cargo.toml

$(PLUGIN_OUT_PATH): BUILD_RESULT="$(PLUGIN_ARTIFACTS_DIR)/$(TARGET_TRIPLE)/release/$(PLUGIN_NAME)"
$(PLUGIN_OUT_PATH): $(PLUGIN_DEPS)
	@echo "  CARGO   $(PLUGIN_NAME) (${TARGET_TRIPLE})"
	@CARGO_TERM_PROGRESS_WHEN=never cargo build --release \
		--target=$(TARGET_TRIPLE) \
		--manifest-path=$(PLUGIN_DIR)/Cargo.toml \
		--target-dir=$(PLUGIN_ARTIFACTS_DIR)
	@mkdir -p $(PLUGIN_BIN_DIR)
	@cp -p $(BUILD_RESULT) $@

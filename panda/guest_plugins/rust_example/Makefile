PLUGIN_DIR = $(realpath $(join $(SRC_PATH), /panda/guest_plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)
PLUGIN_ARTIFACTS_DIR = $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/target

PLUGIN_DEPS=$(RUST_SOURCE) $(PLUGIN_DIR)/Cargo.toml

BUILD_TARGET=$(addprefix build-,$(TARGET_NAME))

all: $(BUILD_TARGET)

build-x86_64: $(PLUGIN_DEPS)
	@echo "  CARGO   $(PLUGIN_NAME)"
	@CARGO_TERM_PROGRESS_WHEN=never cargo build --release \
		--target=x86_64-unknown-linux-musl \
		--manifest-path=$(PLUGIN_DIR)/Cargo.toml \
		--target-dir=$(PLUGIN_ARTIFACTS_DIR)

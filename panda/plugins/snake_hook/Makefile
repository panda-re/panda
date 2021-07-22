PANDA_PATH = $(realpath $(shell pwd)/..)
PLUGIN_DIR = $(realpath $(join $(PANDA_PATH), /../panda/plugins/$(PLUGIN_NAME)/))
RUST_SOURCE = $(wildcard $(PLUGIN_DIR)/src/*.rs)
PLUGIN_ARTIFACTS_DIR = $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/target

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so : $(RUST_SOURCE) $(PLUGIN_DIR)/Cargo.toml
	@echo "CARGO   $(PLUGIN_DIR)"
	@CARGO_TERM_PROGRESS_WHEN=never cargo build --release \
		--no-default-features --features=$(TARGET_NAME) \
		--manifest-path=$(PLUGIN_DIR)/Cargo.toml \
		--target-dir=$(PLUGIN_ARTIFACTS_DIR)
	@cp -p $(PLUGIN_ARTIFACTS_DIR)/release/lib$(PLUGIN_NAME).so $@

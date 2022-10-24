include config-target.mak

ifndef PLUGIN_SRC_ROOT
$(error PLUGIN_SRC_ROOT is not set)
endif
ifndef PLUGIN_NAME
$(error PLUGIN_NAME is not set)
endif

PLUGIN_DIR = $(realpath $(join $(PLUGIN_SRC_ROOT), /$(PLUGIN_NAME)/))
PLUGIN_TARGET_DIR=panda/guest_plugins
PLUGIN_BIN_DIR=$(PLUGIN_TARGET_DIR)/bin
PLUGIN_OUT_PATH=$(PLUGIN_BIN_DIR)/$(PLUGIN_NAME)

export CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_LINKER ?= arm-linux-musleabi-cc
export CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_RUSTFLAGS = -C target-cpu=arm926ej-s

export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER ?= mips-linux-musl-cc
#export CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C linker=mips-linux-musl-cc"

export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER ?= mipsel-linux-musl-cc

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER ?= aarch64-linux-musl-cc

export CARGO_TARGET_MIPS64_UNKNOWN_LINUX_MUSLABI64_LINKER ?= mips64-linux-musl-cc

BUILD_TARGET=$(addprefix build-,$(TARGET_NAME))

all: $(BUILD_TARGET)

build-x86_64: TARGET_TRIPLE=x86_64-unknown-linux-musl
build-x86_64: $(PLUGIN_OUT_PATH)

build-i386: TARGET_TRIPLE=i686-unknown-linux-musl
build-i386: $(PLUGIN_OUT_PATH)

build-arm: TARGET_TRIPLE=armv5te-unknown-linux-musleabi
build-arm: $(PLUGIN_OUT_PATH)

build-aarch64: TARGET_TRIPLE=aarch64-unknown-linux-musl
build-aarch64: $(PLUGIN_OUT_PATH)

build-mips: TARGET_TRIPLE=mips-unknown-linux-musl
build-mips: $(PLUGIN_OUT_PATH)

build-mipsel: TARGET_TRIPLE=mipsel-unknown-linux-musl
build-mipsel: $(PLUGIN_OUT_PATH)

build-mips64: TARGET_TRIPLE=mips64-unknown-linux-muslabi64
build-mips64: $(PLUGIN_OUT_PATH)

# Do not build for PowerPC
build-ppc: ;

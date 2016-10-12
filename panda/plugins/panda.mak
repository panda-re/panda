# Note: We will be run from target directory. (build/target)

include ../config-host.mak
include config-devices.mak
include config-target.mak
include $(SRC_PATH)/rules.mak

ifdef EXTRA_PLUGINS_PATH
$(call set-vpath, $(SRC_PATH):$(EXTRA_PLUGINS_PATH):$(BUILD_DIR))
else
$(call set-vpath, $(SRC_PATH):$(BUILD_DIR))
endif

PLUGIN_TARGET_DIR=panda/plugins
PLUGIN_OBJ_DIR=panda/plugins/$(PLUGIN_NAME)

PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)

TARGET_PATH=$(SRC_PATH)/target-$(TARGET_BASE_ARCH)

QEMU_CFLAGS+=-DNEED_CPU_H -fPIC
QEMU_CXXFLAGS+=-DNEED_CPU_H -fPIC

QEMU_CXXFLAGS+=-fpermissive -std=c++11

# These are all includes. I think.
QEMU_CFLAGS+=$(GLIB_CFLAGS)
QEMU_CXXFLAGS+=$(GLIB_CFLAGS)

QEMU_INCLUDES+=-I$(PLUGIN_SRC_DIR) -I$(PLUGIN_SRC_ROOT) -I$(SRC_PATH)/panda/plugins
QEMU_INCLUDES+=-I$(PLUGIN_TARGET_DIR) -I.. -I$(TARGET_PATH)

# These should get generated automatically and include dependency information.
-include $(wildcard $(PLUGIN_OBJ_DIR)/*.d)

# You can override this recipe by using the full name of the plugin in a
# plugin Makefile. (e.g. $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so).
$(PLUGIN_TARGET_DIR)/panda_%.so:
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) $(LDFLAGS_SHARED) -o $@ $^ $(LIBS),"  PLUG  $(TARGET_DIR)$@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

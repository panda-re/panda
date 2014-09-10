# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=bir

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
# LIBS+=
QEMU_CFLAGS+=-std=c++11
QEMU_CFLAGS+=-lm
QEMU_CFLAGS+=-Wno-unused-result -Wno-unused-variable

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp
$(PLUGIN_TARGET_DIR)/bir_utils.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/bir_utils.cpp




O_FILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
O_FILES+=$(PLUGIN_TARGET_DIR)/bir_utils.o


$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so



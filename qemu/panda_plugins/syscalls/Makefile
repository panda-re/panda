# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=syscalls
# uncomment to enable FDTRACKER module
#ENABLE_FDTRACKER=1

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CFLAGS+=-std=c++11
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp
$(PLUGIN_TARGET_DIR)/weak_callbacks.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/weak_callbacks.cpp
$(PLUGIN_TARGET_DIR)/fdtracker.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/fdtracker.cpp

O_FILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
ifdef ENABLE_FDTRACKER
O_FILES+=$(PLUGIN_TARGET_DIR)/fdtracker.o
endif
# any syscall handlers have to be linked in prior to the default empty handlers in weak_callbacks
O_FILES+=$(PLUGIN_TARGET_DIR)/weak_callbacks.o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

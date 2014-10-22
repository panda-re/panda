# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=fdtracker

# Include the PANDA Makefile rules
include ../panda.mak

GENDIR=$(PLUGIN_TARGET_DIR)/syscalls
GENERATED_HEADERS+= $(GENDIR)/gen_syscalls_ext_typedefs.h

# If you need custom CFLAGS or LIBS, set them up here
CXXFLAGS+= -std=c++11 -I$(GENDIR) -Wno-unused-function
# LIBS+=

$(PLUGIN_SRC_DIR)/$(PLUGIN_NAME).cpp: $(PLUGIN_SRC_DIR)/syscalls/syscalls_common.hpp

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CXX) $(QEMU_CXXFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=osi

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
# LIBS+=
# CFLAGS+=-save-temps
CXXFLAGS+=-std=c++11

PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/os_intro.o
ifneq (,$(findstring -DOSI_PROC_EVENTS,$(QEMU_CFLAGS)))
PLUGIN_OBJFILES+=$(PLUGIN_OBJ_DIR)/osi_proc_events.o
endif

.PHONY: all

# Plugin dynamic library. Please stick with the panda_ naming convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_OBJ_DIR) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so


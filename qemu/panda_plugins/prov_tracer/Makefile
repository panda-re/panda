# Don't forget to add your plugin to config.panda!
PLUGIN_NAME=prov_tracer

# Include the PANDA Makefile rules
include ../panda.mak

# Location of the linux headers and source. Used to process kernel data structures.
LINUX_HEADERS=/usr/src/linux-headers
LINUX_SOURCE=/usr/src/linux

# Dynamic libraries for translating system calls.
LINUX_SYSCALLENTS_DL=$(foreach f,\
					 $(subst .c,.so,$(wildcard syscallents_linux-*.c)),\
					 $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_$(f)\
)

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CFLAGS+=-std=c++11
#CXXFLAGS+=-DXXX
#CFLAGS+=-DXXX
LIBS+=-ldistorm3

OBJFILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_syscallents_%.so: syscallents_%.c
	$(call quiet-command,$(CC) -shared -o $@ $^,"  SYSCALL DEFS  $@")

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(OBJFILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so $(LINUX_SYSCALLENTS_DL)


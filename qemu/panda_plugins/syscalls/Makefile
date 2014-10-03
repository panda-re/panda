# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=syscalls
# uncomment to enable FDTRACKER module
# ENABLE_FDTRACKER=1

# Include the PANDA Makefile rules
include ../panda.mak

ifeq ($(TARGET_BASE_ARCH),arm)
SYSCALLS_PROTOS=android_arm_prototypes.txt
SYSCALLS_ARCH=arm
else
SYSCALLS_PROTOS=linux_x86_prototypes.txt
SYSCALLS_ARCH=x86
endif

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CFLAGS+=-std=c++11
# LIBS+=

# uncomment to enable taint in the FDTRACKER
# QEMU_CFLAGS+= -DFDTRACKER_ENABLE_TAINT

PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)

GENCODE=$(PLUGIN_SRC_DIR)/gen_syscall_ppp_boilerplate.cpp
GENCODE+= $(PLUGIN_SRC_DIR)/gen_syscall_ppp_register.cpp
GENCODE+= $(PLUGIN_SRC_DIR)/gen_syscall_printer.cpp
GENCODE+= $(PLUGIN_SRC_DIR)/gen_callbacks.hpp
GENCODE+= $(PLUGIN_SRC_DIR)/gen_default_callbacks.cpp
GENCODE+= $(PLUGIN_SRC_DIR)/gen_syscalls_ext_typedefs.h

$(PLUGIN_SRC_DIR)/gen_%: linux_syscall_parser.py
	$(call quiet-command,python linux_syscall_parser.py $(SYSCALLS_PROTOS) $(SYSCALLS_ARCH),"  PYTHON linux_syscall_parser.py")

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp $(GENCODE)
$(PLUGIN_TARGET_DIR)/weak_callbacks.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/weak_callbacks.cpp $(GENCODE)
$(PLUGIN_TARGET_DIR)/fdtracker.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/fdtracker.cpp $(GENCODE)

O_FILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
ifdef ENABLE_FDTRACKER
O_FILES+=$(PLUGIN_TARGET_DIR)/fdtracker.o
endif

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

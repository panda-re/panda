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

GENDIR=$(PLUGIN_TARGET_DIR)/syscalls

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CXXFLAGS+=-std=c++11 -I$(GENDIR)
# LIBS+=

# uncomment to enable taint in the FDTRACKER
# QEMU_CFLAGS+= -DFDTRACKER_ENABLE_TAINT

GENERATED_HEADERS+= $(GENDIR)/gen_syscall_ppp_boilerplate.cpp
GENERATED_HEADERS+= $(GENDIR)/gen_syscall_ppp_register.cpp
GENERATED_HEADERS+= $(GENDIR)/gen_syscall_printer.cpp
GENERATED_HEADERS+= $(GENDIR)/gen_callbacks.hpp
GENERATED_HEADERS+= $(GENDIR)/gen_default_callbacks.cpp
GENERATED_HEADERS+= $(GENDIR)/gen_syscalls_ext_typedefs.h

GENPATTERN=$(shell echo $(GENERATED_HEADERS) | sed s/gen_/%/g)

$(GENDIR):
	$(call quiet-command,mkdir -p $(GENDIR),"  MKDIR $(GENDIR)")

$(GENPATTERN): linux_syscall_parser.py $(GENDIR) $(SYSCALLS_PROTOS)
	$(call quiet-command,python linux_syscall_parser.py $(SYSCALLS_PROTOS) $(SYSCALLS_ARCH) $(GENDIR),"  GEN   $(GENDIR)")

PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)
SYSCALLS_HEADERS = $(PLUGIN_SRC_DIR)/syscalls.hpp
SYSCALLS_HEADERS+= $(PLUGIN_SRC_DIR)/syscalls_common.hpp

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp $(GENERATED_HEADERS) $(SYSCALLS_HEADERS)
$(PLUGIN_TARGET_DIR)/weak_callbacks.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/weak_callbacks.cpp $(GENERATED_HEADERS) $(SYSCALLS_HEADERS)

O_FILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=syscalls2
# uncomment to enable FDTRACKER module
# ENABLE_FDTRACKER=1

# Include the PANDA Makefile rules
include ../panda.mak


# If you need custom CFLAGS or LIBS, set them up here
QEMU_CXXFLAGS+=-std=c++11 #  -I$(GENDIR)
# LIBS+=

# uncomment to enable taint in the FDTRACKER
# QEMU_CFLAGS+= -DFDTRACKER_ENABLE_TAINT

PLUGIN_SRC_DIR=$(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)
SYSCALLS_HEADERS = $(PLUGIN_SRC_DIR)/syscalls2.h
SYSCALLS_HEADERS+= $(PLUGIN_SRC_DIR)/syscalls_common.h


# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp $(GENERATED_HEADERS) $(SYSCALLS_HEADER)
$(PLUGIN_TARGET_DIR)/weak_callbacks.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/weak_callbacks.cpp $(GENERATED_HEADERS) $(SYSCALLS_HEADERS)

O_FILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES) \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_enter_linux_arm.o  \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_return_linux_arm.o  \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_enter_linux_x86.o  \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_return_linux_x86.o  \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_enter_windowsxp_sp2_x86.o \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_return_windowsxp_sp2_x86.o \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_enter_windowsxp_sp3_x86.o \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_return_windowsxp_sp3_x86.o \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_enter_windows7_x86.o \
	$(PLUGIN_TARGET_DIR)/gen_syscall_switch_return_windows7_x86.o
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")


all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

# Don't forget to add your plugin to config.panda!
PLUGIN_NAME=prov_tracer

# Include the PANDA Makefile rules
include ../panda.mak

# Set compler flags.
LINUX_VMI_INCLUDES=-I$(PLUGIN_SRC_ROOT)/linux_vmi
QEMU_CFLAGS+=-DCONFIG_PANDA_VMI
QEMU_CXXFLAGS+=-DCONFIG_PANDA_VMI
#CFLAGS+=-DXXX
CXXFLAGS+=-std=c++11
LIBS+=-ldistorm3

# Dynamic libraries for translating system calls.
# Use gen_tables_linux.py script to generate these.
LINUX_SYSCALLENTS_DL=$(foreach f,\
					 $(subst .c,.so,$(wildcard syscallents_linux-*.c)),\
					 $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_$(f)\
)

# Linux VMI object files - kept separate from the standalone linux_vmi plugin.
LINUX_VMI_OBJDIR=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)
LINUX_VMI_OBJFILES=$(LINUX_VMI_OBJDIR)/DECAF_linux_vmi.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DECAF_main.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DroidScope/DS_Init.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DroidScope/DS_utils/SymbolMap.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DroidScope/linuxAPI/Context.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DroidScope/linuxAPI/ModuleServer.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/DroidScope/linuxAPI/ProcessInfo.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/utils/TULStringMapWrapper.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/utils/OutputWrapper.o
LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/utils/HelperFunctions.o
#LINUX_VMI_OBJFILES+=$(LINUX_VMI_OBJDIR)/linux_vmi_main.o

# All object files used by the plugin.
PLUGIN_OBJFILES=$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o $(LINUX_VMI_OBJFILES)

.PHONY: all

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/%.o: $(PLUGIN_SRC_ROOT)/linux_vmi/%.c
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CC) $(LINUX_VMI_INCLUDES) $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(CFLAGS) -c -o $@ $^,"  LINUX VMI CC $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)/%.o: $(PLUGIN_SRC_ROOT)/linux_vmi/%.cpp
	@[ -d  $(dir $@) ] || mkdir -p $(dir $@)
	$(call quiet-command,$(CXX) $(LINUX_VMI_INCLUDES) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_INCLUDES) $(QEMU_CFLAGS) $(QEMU_CXXFLAGS) $(CXXFLAGS)) -c -o $@ $^,"  LINUX VMI CXX $@")

$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)_syscallents_%.so: syscallents_%.c
	$(call quiet-command,$(CC) -shared -o $@ $^,"  SYSCALL DEFS  $@")

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)
	$(call quiet-command,$(CXX) $(filter-out $(CXXFLAGS_EXCLUDE), $(QEMU_CFLAGS)) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so $(LINUX_SYSCALLENTS_DL)


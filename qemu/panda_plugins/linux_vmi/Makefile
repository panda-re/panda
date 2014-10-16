# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=linux_vmi

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
QEMU_CXXFLAGS+=-std=c++11
# LIBS+=

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
#$(PLUGIN_TARGET_DIR)/DECAF_linux_vmi.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DECAF_linux_vmi.c
#$(PLUGIN_TARGET_DIR)/DECAF_main.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DECAF_main.c
#$(PLUGIN_TARGET_DIR)/linux_vmi_main.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/linux_vmi_main.cpp
#$(PLUGIN_TARGET_DIR)/oidScope/DS_Init.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DroidScope/DS_Init.c
#$(PLUGIN_TARGET_DIR)/Context.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DroidScope/linuxAPI/Context.c
#$(PLUGIN_TARGET_DIR)/ModuleServer.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DroidScope/linuxAPI/ModuleServer.cpp
#$(PLUGIN_TARGET_DIR)/ProcessInfo.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/DroidScope/linuxAPI/ProcessInfo.cpp


O_FILES=$(PLUGIN_TARGET_DIR)/DECAF_linux_vmi.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DECAF_main.o
O_FILES+=$(PLUGIN_TARGET_DIR)/linux_vmi_main.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DroidScope/DS_Init.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DroidScope/DS_utils/SymbolMap.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DroidScope/linuxAPI/Context.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DroidScope/linuxAPI/ModuleServer.o
O_FILES+=$(PLUGIN_TARGET_DIR)/DroidScope/linuxAPI/ProcessInfo.o
O_FILES+=$(PLUGIN_TARGET_DIR)/utils/TULStringMapWrapper.o
O_FILES+=$(PLUGIN_TARGET_DIR)/utils/OutputWrapper.o
O_FILES+=$(PLUGIN_TARGET_DIR)/utils/HelperFunctions.o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES)
	$(call quiet-command,$(CXX) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so

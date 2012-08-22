PLUGIN_NAME=sample

include ../panda.mak

panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $(SRC_PATH)/$(TARGET_DIR)/$@ $^ $(LIBS),"  PLUGIN  $@")

all: panda_$(PLUGIN_NAME).so

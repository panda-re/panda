# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# LIBS+=
# CFLAGS+=-save-temps

PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/os_intro.o
ifneq (,$(findstring -DOSI_PROC_EVENTS,$(QEMU_CFLAGS)))
PLUGIN_OBJFILES+=$(PLUGIN_OBJ_DIR)/osi_proc_events.o
endif

# Plugin dynamic library. At ../panda_$(PLUGIN_NAME).so
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)

# Don't forget to add your plugin to config.panda!

# The main rule for your plugin. List all object-file dependencies.
O_FILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(O_FILES) \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_enter_linux_arm.o  \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_return_linux_arm.o  \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_enter_linux_x86.o  \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_return_linux_x86.o  \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_enter_windowsxp_sp2_x86.o \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_return_windowsxp_sp2_x86.o \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_enter_windowsxp_sp3_x86.o \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_return_windowsxp_sp3_x86.o \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_enter_windows7_x86.o \
	$(PLUGIN_OBJ_DIR)/gen_syscall_switch_return_windows7_x86.o

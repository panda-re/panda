# Don't forget to add your plugin to config.panda!

# The main rule for your plugin. List all object-file dependencies.
O_FILES=$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o $(PLUGIN_OBJ_DIR)/syscalls2_info.o

# Syscall switch files
SYSCALL_SWITCH_SRC=$(basename $(notdir $(wildcard $(PLUGIN_SRC_DIR)/gen_syscall_switch_*.cpp)))
SYSCALL_SWITCH_OBJ=$(addprefix $(PLUGIN_OBJ_DIR)/,$(addsuffix .o,$(SYSCALL_SWITCH_SRC)))

# Syscall info files
SYSCALL_INFO_SRC=$(basename $(notdir $(wildcard $(PLUGIN_SRC_DIR)/gen_syscall_info_*.c)))
SYSCALL_INFO_DSO=$(addprefix $(PLUGIN_TARGET_DIR)/dso_$(PLUGIN_NAME)_,$(addsuffix $(DSOSUF),$(SYSCALL_INFO_SRC)))

.PHONY: all

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF): $(O_FILES) $(SYSCALL_SWITCH_OBJ)

all: $(SYSCALL_INFO_DSO) $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME)$(DSOSUF)


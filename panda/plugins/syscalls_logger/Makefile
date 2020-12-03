# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
LIBS += -ljsoncpp
CFLAGS += -std=c++17

# Mult-src setup
SYSCALLS_LOGGER_SRC  = $(notdir $(wildcard $(PLUGIN_SRC_DIR)/*.cpp))
SYSCALLS_LOGGER_OBJ  = $(patsubst %.cpp,$(PLUGIN_OBJ_DIR)/%.o,$(SYSCALLS_LOGGER_SRC))

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(SYSCALLS_LOGGER_OBJ)
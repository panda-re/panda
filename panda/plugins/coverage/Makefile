# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
LIBS+=-lcapstone

$(PLUGIN_OBJ_DIR)/coverage.py: $(PLUGIN_SRC_DIR)/coverage.py
	$(call quiet-command,cp $< $@,"CP      $(TARGET_DIR)$@")

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
    $(PLUGIN_OBJ_DIR)/osi_subject.o \
    $(PLUGIN_OBJ_DIR)/OsiObserver.o \
    $(PLUGIN_OBJ_DIR)/Predicate.o \
    $(PLUGIN_OBJ_DIR)/InKernelPredicate.o \
    $(PLUGIN_OBJ_DIR)/PcRangePredicate.o \
    $(PLUGIN_OBJ_DIR)/ExcludedPcRangePredicate.o \
    $(PLUGIN_OBJ_DIR)/CompoundPredicate.o \
    $(PLUGIN_OBJ_DIR)/AlwaysTruePredicate.o \
    $(PLUGIN_OBJ_DIR)/PredicateBuilder.o \
    $(PLUGIN_OBJ_DIR)/AsidBlockGenerator.o \
    $(PLUGIN_OBJ_DIR)/AsidBlockCsvWriter.o \
    $(PLUGIN_OBJ_DIR)/OsiBlockGenerator.o \
    $(PLUGIN_OBJ_DIR)/OsiBlockCsvWriter.o \
    $(PLUGIN_OBJ_DIR)/EdgeCsvWriter.o \
    $(PLUGIN_OBJ_DIR)/EdgeInstrumentationDelegate.o \
    $(PLUGIN_OBJ_DIR)/BlockInstrumentationDelegate.o \
    $(PLUGIN_OBJ_DIR)/CoverageMonitorDelegate.o \
    $(PLUGIN_OBJ_DIR)/InstrumentationDelegate.o \
    $(PLUGIN_OBJ_DIR)/metadata_writer.o \
    $(PLUGIN_OBJ_DIR)/ModeBuilder.o

all: $(PLUGIN_OBJ_DIR)/coverage.py

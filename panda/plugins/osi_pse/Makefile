M4?=m4
DOT?=dot

%.dot: %.dot.m4
	 $(M4) <  $(<) > $(@)

%.pdf: %.dot
	$(DOT) -Tpdf $(<) -o $(@)

%.png: %.dot
	$(DOT) -Tpdf $(<) -o $(@)

#CFLAGS += -DPANDA_LOG_LEVEL=PANDA_LOG_ERROR
#CFLAGS += -DOSI_PSE_ALT_VFORK
#LIBS   += ...
PLUGIN_OBJFILES = $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
				  $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME)_linux.o \
				  $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME)_generic.o

$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_OBJFILES)

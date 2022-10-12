# -*- Mode: makefile -*-
#
# This Makefile example is fairly independent from the main makefile
# so users can take and adapt it for their build. We only really
# include config-host.mak so we don't have to repeat probing for
# programs that the main configure has already done for us.
#

include config-host.mak

TOP_SRC_PATH = $(SRC_PATH)/../..

VPATH += $(SRC_PATH)

NAMES :=
NAMES += execlog
NAMES += hotblocks
NAMES += hotpages
NAMES += howvec
NAMES += lockstep
NAMES += hwprofile
NAMES += cache
NAMES += drcov
NAMES += pandummy
NAMES += syscalls
NAMES += syscalls_logger
NAMES += sc_file_log
NAMES += stringsearch

SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

# The main QEMU uses Glib extensively so it's perfectly fine to use it
# in plugins (which many example do).
PLUGIN_CFLAGS := $(shell $(PKG_CONFIG) --cflags glib-2.0)
PLUGIN_CFLAGS += -fPIC -Wall
PLUGIN_CFLAGS += -I$(TOP_SRC_PATH)/include/qemu

CPPFLAGS = $(GLIB_CFLAGS)
CPPFLAGS += -fPIC -Wall
CPPFLAGS += $(if $(findstring no-psabi,$(QEMU_CFLAGS)),-Wpsabi)
CPPFLAGS += -idirafter $(SRC_PATH)/include/qemu

all: $(SONAMES)


libstringsearch.so: stringsearch.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

stringsearch.o: stringsearch.cpp
	g++  $(CPPFLAGS) -DCURRENT_PLUGIN=\"stringsearch\" -c -o stringsearch.o $<

libosi_linux.so: osi_linux.o default_profile.o kernelinfo_read.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

osi_linux.o: osi_linux/osi_linux.cpp
	$(CC) $(CPPFLAGS) -DCURRENT_PLUGIN=\"osi_linux\" -c -o $@ $<

default_profile.o: osi_linux/default_profile.cpp
	$(CC) $(CPPFLAGS) -DCURRENT_PLUGIN=\"osi_linux\" -c -o $@ $<

kernelinfo_read.o: osi_linux/utils/kernelinfo/kernelinfo_read.c osi_linux/utils/kernelinfo/kernelinfo.h
	$(CC) $(CPPFLAGS) -DCURRENT_PLUGIN=\"osi_linux\" -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $(PLUGIN_CFLAGS) -c -o $@ $<

lib%.so: %.o
ifeq ($(CONFIG_DARWIN),y)
	$(CC) -bundle -Wl,-undefined,dynamic_lookup -o $@ $^ $(LDLIBS)
else
	$(CC) -shared -o $@ $^ $(LDLIBS)
endif

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
.SECONDARY:

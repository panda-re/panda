TARGETS = recctrlu
CFLAGS ?= -O0
LDFLAGS ?= -static

ifeq ($(ARCH),armel)
CC = arm-linux-gnueabi-gcc
CFLAGS_ARCH ?= -marm
endif
ifeq ($(ARCH),x86_64)
CFLAGS_ARCH ?= -m64
endif
CFLAGS_ARCH ?= -m32
CFLAGS += $(CFLAGS_ARCH)

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS)


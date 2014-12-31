
# Default for 32/64-bit x86. Change to TARGET_ARM for ARM.
ARCH = TARGET_I386

CC = gcc

CFLAGS = -MMD -m32 -Wall

all: pirate_label pirate_query

pirate_label: pirate_label.c
	$(CC) $(CFLAGS) -D$(ARCH) -o $@ $<

pirate_query: pirate_query.c
	$(CC) $(CFLAGS) -D$(ARCH) -o $@ $<

clean:
	rm -rf pirate_label pirate_query *.d

-include *.d


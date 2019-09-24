all: toy

CFLAGS += -m32 -g -DHAVE_CONFIG_H -I. -gdwarf-2 -O0

LIBOBJ = toy-pre.o

.SECONDARY:
%-pre.c :
	$(CC) $(CFLAGS) -D'__attribute__(x)=' -include stdio.h -E $<  -o $@ $(shell echo "$@" | sed -e "s/-pre//")
	sed -i '/^#/ d' $@

%.o : %.c
	$(CC) $(CFLAGS) -c $<  -o $@  

toy: $(LIBOBJ)
	$(CC) $(CFLAGS) -o $@ $<

install:
	mkdir -p lava-install/bin
	cp toy lava-install/bin

preclean:
	rm -f toy-pre.c

clean:
	rm -f $(LIBOBJ) toy

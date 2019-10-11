all: toy

CFLAGS += -m32 -g -DHAVE_CONFIG_H -I. -gdwarf-2 -O0

%.o : %.c
	$(CC) $(CFLAGS) -c $<  -o $@  

toy: toy.c
	$(CC) $(CFLAGS) -o $@ $<

install:
	mkdir -p lava-install/bin
	cp toy lava-install/bin

clean:
	rm -f toy

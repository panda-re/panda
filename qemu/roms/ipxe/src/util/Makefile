BLIB = ../bin/blib.a
CFLAGS = -Os

all : hijack prototester mucurses_test

hijack : hijack.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Wall -lpcap -o $@ $<

prototester.o : prototester.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Wall -o $@ -c $< -idirafter ../include

prototester : prototester.o $(BLIB)
	$(CC) -o $@ $< -lc $(BLIB)

mucurses_test.o : mucurses_test.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -Wall -o $@ -c $<

mucurses_test : mucurses_test.o $(BLIB)
	$(CC) -o $@ $< -lc $(BLIB)

clean :
	rm -f hijack prototester mucurses_test *.o

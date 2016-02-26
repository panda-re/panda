

 
all: pandalog_reader

pandalog.pb-c.o: pandalog.pb-c.c
	gcc -c pandalog.pb-c.c -I .. -g -O0

pandalog_print.o: pandalog_print.c 
	gcc -c pandalog_print.c  -g -O0 

pandalog.o: pandalog.c
	gcc -c pandalog.c -I .. -D PANDALOG_READER  -g -O0

pandalog_reader.o: pandalog_reader.c
	gcc -c pandalog_reader.c  -g -O0

pandalog_reader: pandalog.o pandalog.pb-c.o pandalog_print.o pandalog_reader.o
	gcc -o pandalog_reader pandalog.o   pandalog.pb-c.o  pandalog_print.o  pandalog_reader.o -L/usr/local/lib -lprotobuf-c -g -O0  -I .. -lz 



clean:
	rm pandalog.o   pandalog.pb-c.o  pandalog_print.o  pandalog_reader.o


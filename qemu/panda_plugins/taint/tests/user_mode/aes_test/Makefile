all: aestool

aestool: aestool.c AES/aes.c AES/aes.h ../../include/gcc-x86_64/panda_mark.h
	gcc -g -I AES -I ../../include/gcc-x86_64 -o aestool aestool.c AES/aes.c

clean:
	rm -f aestool

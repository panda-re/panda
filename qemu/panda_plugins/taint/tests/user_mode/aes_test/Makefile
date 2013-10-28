all: aestool

aestool: aestool.c AES/aes.c AES/aes.h ../panda_mark.h
	gcc -g -I AES -I .. -o aestool aestool.c AES/aes.c

clean:
	rm -f aestool

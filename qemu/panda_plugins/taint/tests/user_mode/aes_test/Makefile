all: aestool

TARGET ?= TARGET_I386

aestool:
	gcc -g -D $(TARGET) -I AES -I ../../include/gcc -o aestool aestool.c AES/aes.c

clean:
	rm -f aestool

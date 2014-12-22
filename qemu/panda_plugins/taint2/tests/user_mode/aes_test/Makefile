all: aestool

TARGET ?= TARGET_I386

aestool:
	clang -m32 -g -D $(TARGET) -I AES -I ../../include/gcc -o aestool aestool.c AES/aes.c

clean:
	rm -f aestool

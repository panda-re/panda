ARCH=i386
CFLAGS=-m32 -static -march=${ARCH} -fno-stack-protector

all: user_prog

user_prog: user_prog.c
	$(CC) ${CFLAGS} $^ -o $@

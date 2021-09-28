.DEFAULT_GOAL := all
LIST=hello_world read_file read_all_files injector tiny_mmap

all: $(LIST)

.PHONY: all

CC=gcc -m32
EXTRA_GCC_ARGS= -fomit-frame-pointer -nodefaultlibs -nostdlib -fpic


hello_world: hello_world.c
	$(CC) $(EXTRA_GCC_ARGS) $< -o $@

read_file: read_file.c
	$(CC) $(EXTRA_GCC_ARGS) $< -o $@

read_all_files: read_all_files.c
	$(CC) $(EXTRA_GCC_ARGS) $< -o $@

injector: injector.c
	$(CC) -O3 $(EXTRA_GCC_ARGS) $< -o $@

tiny_mmap: tiny_mmap.c
	$(CC) $(EXTRA_GCC_ARGS) $< -o $@

basic_hello_world: basic_hello_world.c
	$(CC) -static $< -o $@

clean: 
	rm -rf  $(LIST)
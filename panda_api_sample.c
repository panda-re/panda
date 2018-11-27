// gcc -g  -o papi panda_api_sample.c ./build/i386-softmmu/libpanda-i386.so
#include "panda/include/panda/panda_api.h"
#include <string.h>

int main(int argc, char **argv) {

    argv[0] = strdup("/home/tleek/pypanda/build/i386-softmmu/qemu-system-i386");
    panda_init(argc, argv, 0);

    panda_replay("/home/tleek/tmp/toy/toy");

    panda_run();
}

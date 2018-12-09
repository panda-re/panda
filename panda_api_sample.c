// gcc -g  -o papi panda_api_sample.c ./build/i386-softmmu/libpanda-i386.so
#include "panda/include/panda/panda_api.h"
#include <string.h>

int main(int argc, char **argv) {

    argv[0] = strdup("/home/luke/panda_luke_new/build/i386-softmmu/qemu-system-i386");
    panda_init(argc, argv, 0);

    panda_replay("/home/luke/recordings/recording_in_new_panda");

    panda_run();
}

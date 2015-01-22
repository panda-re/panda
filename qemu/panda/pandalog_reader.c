
// cd panda/qemu
// gcc -g -o pandalog_reader pandalog_reader.c pandalog.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"


int main (int argc, char **argv) {
    pandalog_open(argv[1], "r");
    Panda__LogEntry *ple;
    while (1) {
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }
        printf ("instr=%lld  pc=0x%x : ", ple->instr, ple->pc);
        if (ple->has_asid) {
            printf (" asid=%x", ple->asid);
        }
        if (ple->has_process_id != 0) {
            printf (" pid=%d", ple->process_id);
        }
        if (ple->process_name != 0) {
            printf (" process=[%s]", ple->process_name);
        }
        printf ("\n");
        panda__log_entry__free_unpacked(ple, NULL);
    }
}

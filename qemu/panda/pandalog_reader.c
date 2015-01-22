
// gcc -o pandalog_reader pandalog_reader.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.pb-c.h"



Panda__LogEntry *readstdin() {
    char buf[1024];
    size_t len;
    size_t n = fread((void *) &len, sizeof(len), 1, stdin);
    if (n==0) return NULL;
    n = fread(buf, len, 1, stdin);
    if (n==0) return NULL;
    return panda__log_entry__unpack(NULL, len, buf);
}


int main (int argc, char **argv) {
    Panda__LogEntry *ple;
    while (1) {
        ple = readstdin();
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

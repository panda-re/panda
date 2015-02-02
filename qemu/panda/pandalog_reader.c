
// cd panda/qemu
// g++ -g -o pandalog_reader pandalog_reader.c pandalog.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER

#define __STDC_FORMAT_MACROS


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

        // from asidstory / osi
        if (ple->has_asid) {
            printf (" asid=%x", ple->asid);
        }
        if (ple->has_process_id != 0) {
            printf (" pid=%d", ple->process_id);
        }
        if (ple->process_name != 0) {
            printf (" process=[%s]", ple->process_name);
        }

        // from file_taint
        if (ple->has_taint_label_number) {
            printf (" tl=%d", ple->taint_label_number);
        }
        if (ple->has_taint_label_virtual_addr) {
            printf (" va=0x%llx", ple->taint_label_virtual_addr);
        }
        if (ple->has_taint_label_physical_addr) {
            printf (" pa=0x%llx", ple->taint_label_physical_addr);
        }

        // from tainted_branch
        if (ple->n_tainted_branch_label > 0) {
            printf (" tb=(%d,[", ple->n_tainted_branch_label);
            uint32_t i;
            for (i=0; i<ple->n_tainted_branch_label; i++) {
                printf (" %d", ple->tainted_branch_label[i]);
                if (i+1 < ple->n_tainted_branch_label) {
                    printf (",");
                }
            }
            printf ("])");
        }
        if (ple->n_callstack > 0) {
            printf (" cs=(%d,[",ple->n_callstack);
            uint32_t i;
            for (i=0; i<ple->n_callstack; i++) {
                printf (" 0x%llx", ple->callstack[i]);
                if (i+1 < ple->n_callstack) {
                    printf (",");
                }
            }
            printf ("])");
        }

        printf ("\n");
        panda__log_entry__free_unpacked(ple, NULL);
    }
}

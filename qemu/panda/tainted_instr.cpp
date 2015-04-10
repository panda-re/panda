
// cd panda/qemu
// g++ -g -o tainted_instr tainted_instr.cpp pandalog.c pandalog.pb-c.c  -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER -std=c++11

#define __STDC_FORMAT_MACROS


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"
#include <string.h>

#include <set>
#include <map>

int main (int argc, char **argv) {
    pandalog_open(argv[1], "r");
    bool full = true;
    if (argc == 3 && 0 == (strncmp(argv[2], "summary", 7))) {
        full = false;
    }
    // tainted_pcs[asid] is set of tainted instructions for this asid
    std::map<uint64_t, std::set<uint64_t>> tainted_pcs;
    Panda__LogEntry *ple;
    uint32_t i=0;
    uint64_t current_asid = 0;
    while (1) {
        i ++;
        ple = pandalog_read_entry();
        if (ple == NULL) {
            break;
        }

        if (full) {
            printf ("instr=%" PRIu64 " pc=0x%" PRIx64 " :", ple->instr, ple->pc);
        }
        
        if (ple->has_asid) {
            current_asid = ple->asid;
            if (full) {
                printf (" asid changed to 0x%" PRIx64 , current_asid);
            }                       
        }

        if (full) {
            if (ple->n_callstack > 0) {
                printf (" callstack=(%u,[", (uint32_t) ple->n_callstack);
                uint32_t i;
                for (i=0; i<ple->n_callstack; i++) {
                    printf (" 0x%" PRIx64 , ple->callstack[i]);
                    if (i+1 < ple->n_callstack) {
                        printf (",");
                    }
                }
                printf ("])");
            }
        }

        if (full) {
            if (ple->taint_query_unique_label_set) {
                printf (" taint query unqiue label set: ptr=%" PRIx64" labels: ", ple->taint_query_unique_label_set->ptr);
                uint32_t i;
                for (i=0; i<ple->taint_query_unique_label_set->n_label; i++) {
                    printf ("%d ", ple->taint_query_unique_label_set->label[i]);
                }
            }
        }

        if (ple->taint_query) {
            Panda__TaintQuery *tq = ple->taint_query;
            if (full) {
                printf (" taint query: labels ptr %" PRIx64" tcn=%d ", tq->ptr, tq->tcn);
            }
            tainted_pcs[current_asid].insert(ple->pc);
        }
        panda__log_entry__free_unpacked(ple, NULL);
        if (full) {
            printf ("\n");
        }
    }


    //    printf ("tainted pcs:\n");
    for ( auto kvp : tainted_pcs ) {
        auto asid = kvp.first;
        for ( auto pc : tainted_pcs[asid] ) {
            printf ("asid=0x%" PRIx64"\tpc=%" PRIx64"\n", asid,pc);
        }
    }
   
    printf ("\n");
}

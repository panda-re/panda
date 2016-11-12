
/*
 cd panda/qemu/panda

 gcc -c   pandalog_reader.c  -g
 gcc -c   pandalog.pb-c.c -I .. -g
 gcc -c   pandalog_print.c  -g 
 gcc -c   pandalog.c -I .. -D PANDALOG_READER  -g
 gcc -o pandalog_reader pandalog.o   pandalog.pb-c.o  pandalog_print.o  pandalog_reader.o -L/usr/local/lib -lprotobuf-c -g  -I .. -lz 

*/

#define __STDC_FORMAT_MACROS

extern "C" {

    #include <inttypes.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    //#include "../include/panda/plog.h"
    //#include "../include/panda/plog_print.h"
    #include "panda/plog.h"
    #include "panda/plog_print.h"
}
//#include <map>
//#include <string>

int main (int argc, char **argv) {
    if (argc < 2) {
         printf("USAGE: %s <plog>\n", argv[0]);
         exit(1);
    }
    pandalog_open((const char *) argv[1], (const char*) "r");
    Panda__LogEntry *ple;
    while (1) {
        ple = pandalog_read_entry();
        if (ple == (Panda__LogEntry *)1) {
            continue;
        }
        if (ple == NULL) {
	    break;
        }
        pprint_ple(ple);
#warning Figure out how to properly free ple
        // for some reason this leads to some sort of double-free
        // but i'm leaving in here to investigate further
        // so we don't have leaky plog_readers
        //panda__log_entry__free_unpacked(ple, NULL);
    }
    pandalog_close();
}

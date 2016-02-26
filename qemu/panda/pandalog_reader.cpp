
/*
 cd panda/qemu/panda

 gcc -c   pandalog_reader.c  -g
 gcc -c   pandalog.pb-c.c -I .. -g
 gcc -c   pandalog_print.c  -g 
 gcc -c   pandalog.c -I .. -D PANDALOG_READER  -g
 gcc -o pandalog_reader pandalog.o   pandalog.pb-c.o  pandalog_print.o  pandalog_reader.o -L/usr/local/lib -lprotobuf-c -g  -I .. -lz 

*/

#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"
#include "pandalog_print.h"
//#include <map>
//#include <string>

int main (int argc, char **argv) {
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
//        pprint_ple(ple);
        panda__log_entry__free_unpacked(ple, NULL);
    }
}


// cd panda/qemu/panda
// g++ -g -o pandalog_reader pandalog_reader.cpp pandalog.c pandalog.pb-c.c pandalog_print.c -L/usr/local/lib -lprotobuf-c -I .. -lz -D PANDALOG_READER  -std=c++11

#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "pandalog.h"
#include "pandalog_print.h"
#include <map>
#include <string>

int main (int argc, char **argv) {
    pandalog_open(argv[1], "r");
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
	panda__log_entry__free_unpacked(ple, NULL);
    }
}

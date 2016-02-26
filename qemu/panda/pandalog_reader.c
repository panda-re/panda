
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
    if (argc == 3) {
        if (0 == strcmp("fwd", argv[2])) {
            printf ("reading log in fwd dir\n");
            pandalog_open_read_fwd(argv[1]);
        }
        else if (0 == strcmp("bwd", argv[2])) {
            printf ("reading log in bwd dir\n");
            pandalog_open_read_bwd(argv[1]);
        }
        else {
            assert(1==0);
        }
    }
    else {
        pandalog_open_read_fwd(argv[1]);
    }
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

    }
    pandalog_close();
    

}

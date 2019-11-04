
/*
 * This file is an example of using the C and C++ APIs to read or write pandalog
 * You can either use the pandalog_* functions defined in panda/plog.h, which are C wrappers around the C++ implementation
 * Or the C++ implementation directly, in panda/plog-cc.hpp
 *
 * Note that using the C wrappers requires a few more object files to be linked in (see Makefile.panda.target).
 *
 * You will have to implement your own printing functions.
 *
 * 8/30/17 Ray Wang
 *
*/

#include <fstream>
#include "panda/plog-cc.hpp"

/* plog-cc.cpp dependencies.

   These are needed so we can link with the same version of plog-cc.o that is
   linked with the main PANDA binary.

   As long as this file only calls functions that read a pandalog file, these
   will never be accessed by plog_reader. */

int panda_in_main_loop = 0;
struct CPUTailQ cpus;

target_ulong panda_current_pc(CPUState *env) {
    assert(false);
}

/* *** */

void pprint(std::unique_ptr<panda::LogEntry> ple) {
    if (ple == NULL) {
        printf("PLE is NULL\n");
        return;
    }

    printf("\n{\n");
    printf("\tPC = %" PRId64 "\n", ple->pc());
    printf("\tinstr = %" PRId64 "\n", ple->instr());

    /*if (ple->has_llvmentry()) {*/
        /*pprint_llvmentry(std::move(ple));*/
    /*}*/
    printf("}\n\n");
}

int main (int argc, char **argv) {

    memset(&cpus, 0, sizeof(cpus));

    if (argc < 2) {
         printf("USAGE: %s <plog>\n", argv[0]);
         exit(1);
    }
    
    //write the pandalog
    /*{*/
        /*PandaLog p;*/
       /*p.open((const char*) argv[1], "w");*/
        /*for (int i = 0; i < 3000000; i++){ */
            /*std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());*/
            /*[>ple->mutable_llvmentry()->set_type(i%2);<]*/
            /*[>ple->mutable_llvmentry()->set_address(i%2);<]*/
            /*p.write_entry(std::move(ple));*/
        /*}*/
        /*p.close();*/
    /*}*/
    
    //read the pandalog
    {
        PandaLog p;
        p.open_read_fwd((const char *) argv[1]);
        std::unique_ptr<panda::LogEntry> ple;
        while ((ple = p.read_entry()) != NULL) {
            pprint(std::move(ple));
        }
        p.close();
    }
}

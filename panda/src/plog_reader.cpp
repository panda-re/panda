
/*
 * This file is an example of using the C and C++ APIs to read or write pandalog
 * You can either use the pandalog_* functions defined in panda/plog.h, which are C wrappers around the C++ implementation
 * Or the C++ implementation directly, in panda/plog-cc.hpp
 *
 * Note that using the C wrappers requires a few more object files to be linked in (see Makefile.panda.target).
 *
 * To compile as part of Panda's make,
 * Uncomment two lines in Makefile.panda.target. This will define PLOG_READER, which causes some rr code in plog-cc.cpp to be ignored 
 *
 * To compile standalone:
 * First, compile the plog.proto file to generate the plog.pb.h and plog.pb.cc files 
 * plog.proto is created by combining all the plugins' individual .proto files
 * 
 * protoc -I=$SRC_DIR --cpp_out=$DST_DIR plog.proto
 *
 * Then, assuming headers are in panda/include/panda/
 * g++ -g -o plog_reader_new plog_reader_new.cpp plog.cpp plog.pb.cc -I../include/ -std=c++11 -lz -lprotobuf
 *
 * You will have to implement your own printing functions.
 *
 * 8/30/17 Ray Wang
 *
*/

#define __STDC_FORMAT_MACROS

extern "C" {
    #include <inttypes.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    //#include "panda/plog.h"
}

#include "panda/plog-cc.hpp"

/*void pprint_llvmentry(std::unique_ptr<panda::LogEntry> ple){*/
    /*printf("\tllvmEntry: {\n");*/
    /*printf("\t\ttype = %lu\n", ple->llvmentry().type()); */
    /*printf("\t\taddress = %lx\n", ple->llvmentry().address());*/
    /*printf("\t}\n"); */
/*}*/

void pprint(std::unique_ptr<panda::LogEntry> ple) {
    if (ple == NULL) {
        printf("PLE is NULL\n");
        return;
    }

    printf("\n{\n");
    printf("\tPC = %lu\n", ple->pc());
    printf("\tinstr = %lu\n", ple->instr());

    /*if (ple->has_llvmentry()) {*/
        /*pprint_llvmentry(std::move(ple));*/
    /*}*/
    printf("}\n\n");
}

//void pprint_old(Panda__LogEntry* ple) {
    //if (ple == NULL) {
        //printf("PLE is NULL\n");
        //return;
    //}

    //printf("\n{\n");
    //printf("\tPC = %lu\n", ple->pc);
    //printf("\tinstr = %lu\n", ple->instr);
    //printf("}\n\n");
//}

int main (int argc, char **argv) {
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

    //Use the C interface to read the pandalog
    //pandalog_open((const char *) argv[1], (const char*) "r");
    //Panda__LogEntry *ple;
    //while (1) {
        //ple = pandalog_read_entry();
        //if (ple == (Panda__LogEntry *)1) {
            //continue;
        //}
        //if (ple == NULL) {
            //break;
        //}
        //pprint_old(ple);
    //}
    //pandalog_close();
}



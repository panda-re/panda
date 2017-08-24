
/*
 * This file is an example of using the C++ API of protobuf to read or write pandalog
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
 * To compile as part of Panda's make,
 * Uncomment #define PLOG_READER in plog-cc.cpp, so we won't look for rr functions that we don't need
 * Then, uncomment PLOG_READER_PROG in Makefile.panda.target
 *
 * There's definitely a smarter way to do this that involves linking in a #define PLOG_READER,
 * but I couldn't figure out how to get that to work... 
*/

#define __STDC_FORMAT_MACROS

extern "C" {
    #include <inttypes.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
}

#include "panda/plog-cc.hpp"

void pprint_llvmentry(std::unique_ptr<panda::LogEntry> ple){
    printf("\tllvmEntry: {\n");
    printf("\t\ttype = %lu\n", ple->llvmentry().type()); 
    printf("\t\taddress = %lx\n", ple->llvmentry().address());
    printf("\t}\n"); 
}

void pprint(std::unique_ptr<panda::LogEntry> ple) {
    if (ple == NULL) {
        printf("PLE is NULL\n");
        return;
    }

    printf("\n{\n");
    printf("\tPC = %lu\n", ple->pc());
    printf("\tinstr = %lu\n", ple->instr());

    if (ple->has_llvmentry()) {
        pprint_llvmentry(std::move(ple));
    }
    printf("}\n\n");
}

int main (int argc, char **argv) {
    if (argc < 2) {
         printf("USAGE: %s <plog>\n", argv[0]);
         exit(1);
    }
    
    //write the pandalog
    //{
        //PandaLog p;
       //p.open((const char*) argv[1], "w");
        //for (int i = 0; i < 3000000; i++){ 
            //std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
            //ple->mutable_llvmentry()->set_type(i%2);
            //ple->mutable_llvmentry()->set_address(i%2);
            //p.write_entry(std::move(ple));
        //}
        //p.close();
    //}

    //read the same pandalog back
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

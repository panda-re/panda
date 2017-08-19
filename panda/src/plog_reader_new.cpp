
/*
 *
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
 * You will have to implement your own printing functions
*/

#define __STDC_FORMAT_MACROS

extern "C" {
    #include <inttypes.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
}

#include "panda/plog.hpp"

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
    {
        PandaLog p;
       p.pandalog_open((const char*) argv[1], "w");
        for (int i = 0; i < 3000000; i++){ 
            std::unique_ptr<panda::LogEntry> ple (new panda::LogEntry());
            ple->mutable_llvmentry()->set_type(i%2);
            ple->mutable_llvmentry()->set_address(i%2);
            p.pandalog_write_entry(std::move(ple));
        }
        p.pandalog_close();
    }

    //read the same pandalog back
    {
        PandaLog p;
        p.pandalog_open_read_fwd((const char *) argv[1]);
        std::unique_ptr<panda::LogEntry> ple;
        while ((ple = p.pandalog_read_entry()) != NULL) {
            pprint(std::move(ple));
        }
        p.pandalog_close();
    }
}

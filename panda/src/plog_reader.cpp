
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

void pprint_llvmentry(std::unique_ptr<panda::LogEntry> ple){
    printf("\tllvmEntry: {\n");
    printf("\t pc = %lx(%lu)", ple->llvmentry().pc(), ple->llvmentry().pc());
    if (ple->llvmentry().has_tb_num()){
        printf("\t tb_num = %lu", ple->llvmentry().tb_num());
    }
    printf("\n");

    printf("\t type = %lu\n", ple->llvmentry().type()); 

    if (ple->llvmentry().type() == 20 || ple->llvmentry().type() == 24) {
        printf("\t addrtype = %u\n", ple->llvmentry().addr_type()); 
        printf("\t cpustate_offset = %u\n", ple->llvmentry().cpustate_offset()); 
        printf("\t address = %lx\n", ple->llvmentry().address());
        printf("\t numBytes = %lx\n", ple->llvmentry().num_bytes());
        printf("\t value = %lu(%lx)\n", ple->llvmentry().value(), ple->llvmentry().value());
    }

    printf("\t condition = %u, ", ple->llvmentry().condition());
    printf("\t flags = %x\n", ple->llvmentry().flags());

    if (ple->llvmentry().has_vma_name()) {
        printf("\t vma_name = %s\n", ple->llvmentry().vma_name().c_str());
    }

    if (ple->llvmentry().has_called_func_name()) {
        printf("\t called_func_name = %s\n", ple->llvmentry().called_func_name().c_str());
    }
    //printf("\t}\n"); 
}

void pprint(std::unique_ptr<panda::LogEntry> ple) {
    if (ple == NULL) {
        printf("PLE is NULL\n");
        return;
    }

    // printf("{\n");
    printf("\tPC = %lx\n", ple->pc());
    printf("\tinstr = %lu\n", ple->instr());

    if (ple->has_llvmentry()) {
        pprint_llvmentry(std::move(ple));
    }
    printf("},\n");
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

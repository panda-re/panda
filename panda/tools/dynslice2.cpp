
/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Ray Wang        raywang@mit.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */


/*
 * This plugin contains the core logic to do dynamic slicing on an LLVM bitcode module + tracefile
 * It generates a tracefile that can be used by the same tool to mark llvm bitcode 
 * I can use metadata to mark the llvm bitcode in a pass
 *
 * The C struct is defined in llvm_trace2.proto
 *
 */

#include <vector>

#include "llvm_trace2.h"
#include "Extras.h"
#include "plog.h"

#include "panda/tcg-llvm.h"
#include <iostream>

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"


/*
 * Switch statement to handle all instructions
 * and update the uses and defines lists 
 *
 * Instead of reversing the log, I search through to the end for the last occurrence of the 
 * instruction criterion I want using an LLVM pass (like Giri).
 *
 * Then, with this criterion, I can work backwards and find the uses/definitions. 
 * 
 * I need a working set, uses, and definitions set. 
 *
 *
 */


bool is_ignored(Function *f) {
    StringRef func_name = f->getName();
    if (func_name.startswith("__ld") ||
        func_name.startswith("__st") ||
        func_name.startswith("llvm.memcpy") ||
        func_name.startswith("llvm.memset") ||
        func_name.equals("helper_inb") ||
        func_name.equals("helper_inw") ||
        func_name.equals("helper_inl") ||
        func_name.equals("helper_outb") ||
        func_name.equals("helper_outw") ||
        func_name.equals("helper_outl") ||
        func_name.equals("log_dynval"))
        return true;
    else
        return false;
}


void updateUsesAndDefs(){
	
	
}




void usage(char *prog) {
   fprintf(stderr, "Usage: %s [OPTIONS] <llvm_mod> <dynlog> <criterion> [<criterion> ...]\n",
           prog);
   fprintf(stderr, "Options:\n"
           "  -b                : include branch conditions in slice\n"
           "  -d                : enable debug output\n"
           "  -v                : show progress meter\n"
           "  -a                : just align, don't slice\n"
           "  -w                : print working set after each block\n"
           "  -n NUM -p PC      : skip ahead to TB NUM-PC\n"
           "  -o OUTPUT         : save results to OUTPUT\n"
           "  <llvm_mod>        : the LLVM bitcode module\n"
           "  <dynlog>          : the TUBT log file\n"
           "  <criterion> ...   : the slicing criteria, i.e., what to slice on\n"
           "                      Use REG_[N] for registers, MEM_[PADDR] for memory\n"
          );
}


std::deque<DynVal> workList; 
std::set<> defines; 
std::set<DynVal> uses;
std::vector<traceEntry> traceEntries;

//add stuff to this as needed
struct traceEntry {
	Function *func;
	Instruction *inst;
	
	Panda__LogEntry ple;
	//special snowflake?
}


int main(){
    //parse args 
    
	if (argc < 4) {
		printf("Usage: <llvm-mod.bc> <slice-file>\n");
		return EXIT_FAILURE;   
	}

	int opt;
    unsigned long num, pc;
    bool show_progress = false;
    bool have_num = false, have_pc = false;
    bool print_work = false;
    bool align_only = false;
    const char *output = NULL;
	 
	while ((opt = getopt(argc, argv, "vawbdn:p:o:")) != -1) {
        switch (opt) {
        case 'n':
            num = strtoul(optarg, NULL, 10);
            have_num = true;
            break;
        case 'p':
            pc = strtoul(optarg, NULL, 16);
            have_pc = true;
            break;
        case 'd':
            debug = true;
            break;
        case 'b':
            include_branches = true;
            break;
        case 'w':
            print_work = true;
            break;							   						
        case 'o':
            output = optarg;
            break;
        case 'v':
            show_progress = true;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

	
	char *llvm_mod_fname = argv[optind];
    char *llvm_trace_fname = argv[optind+1];

	//algo: i have several options here.
	// I could reverse the entire trace (nah)	
    // or i could do what giri does and use a pass and BFS.
    // Maintain a working set 
	
	// if mem, search for last occurrence of that physical address	

	//find_slice();
		

	// read trace into file

}


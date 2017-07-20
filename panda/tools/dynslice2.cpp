
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
#include <set>
#include <deque>

#include "panda/plugins/llvm_trace2/functionCode.h"
extern "C" {
#include "panda/plog.h"
}

#include <iostream>

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IRReader/IRReader.h"
#include <llvm/InstVisitor.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Pass.h>
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"

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
 */
extern "C"{

int cpus;
int panda_current_pc;
int panda_in_main_loop;

}
bool is_ignored(llvm::Function *f) {
    llvm::StringRef func_name = f->getName();
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

enum SliceVarType {
    LLVM,
    MEM,
    HOST,
    REG,
    SPEC,
    FRET
};

uint64_t ret_ctr = 0;

typedef std::pair<SliceVarType,uint64_t> SliceVar;
	

//add stuff to this as needed
struct traceEntry {
	llvm::Function *func;
	llvm::Instruction *inst;
	
	Panda__LogEntry ple;
	//special snowflake?
};


std::set<SliceVar> workList; 
std::set<traceEntry> defines; 
std::set<traceEntry> uses;
std::vector<traceEntry> traceEntries;

Panda__LogEntry* cursor; 

void updateUsesAndDefs(){
	
}
/*
 * This function takes in a list of criteria
 * and iterates backwards over an LLVM function
 * updating the global workList, uses, and defs. 
 *
 */
void slice_trace(std::vector<SliceVar> criteria){
	// Iterate every instruction to find its uses and its definition
	// if one of the definitions is in the working list (which contains initial criterion)
	// update working list with the uses 

	//update worklist 
	
	
}

SliceVar VarFromStr(const char *str) {
    SliceVarType typ;
    uint64_t addr = 0;
    char *addrstr;

    char *work = strdup(str);
    char *c = work;
    while (*c) {
        if (*c == '_') {
            *c = '\0';
            addrstr = c+1;
        }
        c++;
    }
    sscanf(addrstr, "%lu", &addr);

    if (strncmp(str, "LLVM", 4) == 0) {
        typ = LLVM;
    }
    else if (strncmp(str, "MEM", 3) == 0) {
        typ = MEM;
    }
    else if (strncmp(str, "REG", 3) == 0) {
        typ = REG;
    }
    else if (strncmp(str, "HOST", 4) == 0) {
        typ = HOST;
    }
    else if (strncmp(str, "SPEC", 4) == 0) {
        typ = SPEC;
    }
    else if (strncmp(str, "RET", 3) == 0) {
        typ = FRET;
    }
    else {
        assert (false && "Bad SliceVarType");
    }

    free(work);

    return std::make_pair(typ, addr);
}

int main(int argc, char **argv){
    //parse args 
    
	if (argc < 4) {
		printf("Usage: <llvm-mod.bc> <trace-file> <criterion> (<criterion>)\n");
		return EXIT_FAILURE;   
	}

	int opt, debug, include_branches;
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
 	 		
    llvm::LLVMContext &ctx = llvm::getGlobalContext();
    llvm::SMDiagnostic err;
    llvm::Module *mod = llvm::ParseIRFile(llvm_mod_fname, err, ctx);

	// read trace into memory

    // Add the slicing criteria
    for (int i = optind + 2; i < argc; i++) {
        workList.insert(VarFromStr(argv[i]));
    }

	printf("Slicing trace\n");

	std::vector<Panda__LogEntry*> ple_vector; 	
	
	pandalog_open_read_fwd(llvm_trace_fname);
	
	Panda__LogEntry *ple;
	// read all pandalog entries into memory. 
	while ((ple = pandalog_read_entry()) != NULL){
		//XXX: This may take up a shitload of memory
		ple_vector.push_back(ple); 
	}
    
    uint64_t ple_idx = ple_vector.size()-1;

	// Process by the function? I'll just do the same thing as dynslice1.cpp for now. 
	while (ple_idx > 0) {
		// while we haven't reached beginning of file yet 
		printf("type is %lu\n", ple_vector[ple_idx]->llvmentry->type);
		
		if (ple_vector[ple_idx]->llvmentry->type == FunctionCode::LLVM_FN){
			printf("FOund an LLVM FUn\n");	 	
			
			// now, align trace and llvm bitcode by creating traceEntries with dynamic info filled in 
			align_trace(ple_vector)
		}
		ple_idx--;
	}
	
	slice_trace(ple_vector);

	pandalog_close();
}



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
#include "panda/plog_print.h"
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

using namespace llvm;

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
        func_name.startswith("record_"))
        return true;
    else
        return false;
}

std::map<FunctionCode, std::string> functionCodeStrings = {
	{FunctionCode::LLVM_FN, "LLVM FUNCTION"},
	{FunctionCode::FUNC_CODE_INST_LOAD, "LOAD"}
};

void pprint_llvmentry(Panda__LogEntry *ple){
	printf("\tllvmEntry: {\n");
	printf("\t\ttype = %lu\n", ple->llvmentry->type); 
	printf("\t}\n"); 
}

void pprint_ple(Panda__LogEntry *ple) {
	if (ple == NULL) {
		printf("PLE is NULL\n");
		return;
	}

	printf("\n{\n");
	printf("\tPC = %lu\n", ple->pc);
	printf("\tinstr = %lu\n", ple->instr);

	if (ple->llvmentry) {
		pprint_llvmentry(ple);
	}
	printf("}\n\n");
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
	
	Panda__LogEntry* ple;
	//special snowflake?
    // memcpy may need another logentry 
};


std::set<SliceVar> workList; 
std::set<SliceVar> defines; 
std::set<SliceVar> uses;
std::vector<traceEntry> traceEntries;

Panda__LogEntry* cursor; 

//void insertAddr(Addr ){

//}

//void insertValue(std::set<SliceVar> &uses, Value* v){

//}

void get_usedefs_Store(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    StoreInst* SI = dyn_cast<StoreInst>(t.inst);
    
    //insertAddr(uses, addr);
    
};

void get_usedefs_Load(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    LoadInst* LI = dyn_cast<LoadInst>(t.inst);

    // Add the memory address to the uses list. 
    // Giri goes back and searches for the stores before this load. Maybe that's better? 

     // Whereas moyix's stuff differentiates addresses and registers when storing in use list
     // I'll do what moyix does for now....
     
    // inserts dynamic address into use list
    //insertAddr(uses, ); 

    //insertValue(uses, );

    //insertValue(defs, t.inst);
    
};

void get_usedefs_Call(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    CallInst* CI = dyn_cast<CallInst>(t.inst);
    

};

void get_usedefs_Ret(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){

};

void get_usedefs_PHI(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){


};

void get_usedefs_Select(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){

};

void get_usedefs_default(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    // by default, add all operands to uselist
    //for (User::op_iterator op = t.inst->op_begin(); op != t.inst->op_end(); op++){
        //Value *v = *op;
        
        //if (!dyn_cast<BasicBlock>(v)){
            //insertValue(uses, v);
        //}

    //}
}

void get_uses_and_defs(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defs) {
    switch (t.inst->getOpcode()) {
        case Instruction::Store:
            get_usedefs_Store(t, uses, defs);
            return;
        case Instruction::Load:
            get_usedefs_Load(t, uses, defs);
            return;
        case Instruction::Call:
            get_usedefs_Call(t, uses, defs);
            return;
        case Instruction::Ret:
            get_usedefs_Ret(t, uses, defs);
            return;
        case Instruction::PHI:
            get_usedefs_PHI(t, uses, defs);
            return;
        case Instruction::Select:
            get_usedefs_Select(t, uses, defs);
            return;
        case Instruction::Unreachable: // how do we even get these??
            return;
        case Instruction::Br:
        case Instruction::Switch:
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::UDiv:
        case Instruction::URem:
        case Instruction::SDiv:
        case Instruction::SRem:
        case Instruction::IntToPtr:
        case Instruction::PtrToInt:
        case Instruction::And:
        case Instruction::Xor:
        case Instruction::Or:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::Trunc:
        case Instruction::BitCast:
        case Instruction::GetElementPtr: // possible loss of precision
        case Instruction::ExtractValue:
        case Instruction::InsertValue:
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr:
        case Instruction::ICmp:
        case Instruction::FCmp:
        case Instruction::Alloca:
            get_usedefs_default(t, uses, defs);
            return;
        default:
            printf("Note: no model for %s, assuming uses={operands} defs={lhs}\n", t.inst->getOpcodeName());
            // Try "default" operand handling
            // defs = LHS, right = operands

            get_usedefs_default(t, uses, defs);
            return;
    }
    return;
}


/*
 * This function takes in a list of criteria
 * and iterates backwards over an LLVM function
 * updating the global workList, uses, and defs. 
 */
void slice_trace(std::vector<traceEntry> &aligned_block, std::vector<SliceVar> &worklist){
		
    //for (std::vector<int>::reverse_iterator ri = aligned_block.rbegin() ; i != aligned_block.rend(); ++it) {
        //if (){
            
        //}

	//}
	
}

bool in_exception = false;

int align_function(std::vector<traceEntry> aligned_block, llvm::Function* f, std::vector<Panda__LogEntry*> ple_vector, int cursor_idx){

	cursor_idx = 0;
	std::reverse(ple_vector.begin(), ple_vector.end());
	ple_vector.erase(ple_vector.begin(), ple_vector.begin()+2);
    BasicBlock &entry = f->getEntryBlock();
    BasicBlock *nextBlock = &entry;
    bool has_successor = true;
    while (has_successor) {
        has_successor = false;
        
        for (BasicBlock::iterator i = nextBlock->begin(), e = nextBlock->end(); i != e; ++i) {
            traceEntry t = {};
            //t.index = insn_index | (bb_index << 16);
            //insn_index++;

			if(in_exception) return cursor_idx;

			//if (ple_vector[cursor_idx]->type == FunctionCode::LLVM_FN){
				
			//}

			// Peek at the next thing in the log. If it's an exception, no point
			// processing anything further, since we know there can be no dynamic
			// values before the exception.
			if (ple_vector[cursor_idx]->llvmentry->type == LLVM_EXCEPTION) {
				printf("Found exception, will not finish this function.\n");
				in_exception = true;
				cursor_idx++;
				return cursor_idx;
			}
			i->dump();

			switch (i->getOpcode()){
				case Instruction::Load: {
					// get the value from the trace 
					//
					Panda__LogEntry* ple = ple_vector[cursor_idx];
					pprint_ple(ple);
					assert (ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_LOAD);
					t.ple = ple;
					t.inst = i;
					t.func = f;

					cursor_idx++;
					aligned_block.push_back(t);
					break;
				}
				case Instruction::Store: {
					StoreInst *s = cast<StoreInst>(i);
					if (s->isVolatile()){
						break;
					}

					Panda__LogEntry* ple = ple_vector[cursor_idx];
					assert (ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_STORE);
					t.ple = ple;
					t.inst = i;
					t.func = f;

					cursor_idx++;
					aligned_block.push_back(t);

					break;
				}
				case Instruction::Br: {
					Panda__LogEntry* ple = ple_vector[cursor_idx];
					assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_BR);
					t.ple = ple;
					t.inst = i;
					t.func = f;

					//update next block to examine
					BranchInst *b = cast<BranchInst>(&*i);
					nextBlock = b->getSuccessor(ple->llvmentry->condition);

					cursor_idx++;
					aligned_block.push_back(t);
					has_successor = true;
					break;
				}
				case Instruction::Switch: {
					Panda__LogEntry* ple = ple_vector[cursor_idx];
					assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_SWITCH);
					
					//update next block to examine
					SwitchInst *s = cast<SwitchInst>(&*i);
					unsigned width = s->getCondition()->getType()->getPrimitiveSizeInBits();
					IntegerType *intType = IntegerType::get(getGlobalContext(), width);
					ConstantInt *caseVal = ConstantInt::get(intType, ple->llvmentry->condition);
					SwitchInst::CaseIt caseIndex = s->findCaseValue(caseVal);
					nextBlock = s->getSuccessor(caseIndex.getSuccessorIndex());
					has_successor = true;

					t.ple = ple;
					t.inst = i;
					t.func = f;

					aligned_block.push_back(t);
					cursor_idx++;
					break;
				}
				case Instruction::PHI: {
					
					// We don't actually have a dynamic log entry here, but for
					// convenience we do want to know which basic block we just
					// came from. So we peek at the previous non-PHI thing in
					// our trace, which should be the predecessor basic block
					// to this PHI
					PHINode *p = cast<PHINode>(&*i);
					Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
					*ple = PANDA__LLVMENTRY__INIT;
					ple->has_phi_index = 1;
					ple->phi_index = -1;
					Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
					new_dyn.llvmentry = ple; // sentinel
					// Find the last non-PHI instruction
					// Search from Reverse beginning (most recent traceEntry) 
					for (auto sit = aligned_block.rbegin(); sit != aligned_block.rend(); sit++) {
						if (sit->inst->getOpcode() != Instruction::PHI) {
							ple->phi_index = p->getBasicBlockIndex(sit->inst->getParent());
							break;
						}
					}
					t.func = f; t.inst = i;
					t.ple = &new_dyn;
					aligned_block.push_back(t);
					cursor_idx++;
					break;
				}
				case Instruction::Select: {
					Panda__LogEntry* ple = ple_vector[cursor_idx];
					assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_SELECT);

					t.ple = ple;
					t.inst = i;
					t.func = f;

					aligned_block.push_back(t);
					cursor_idx++;
					break;
				}
				case Instruction::Call: {
					//update next block to be inside calling function. 
					CallInst *call = cast<CallInst>(&*i);
					Function *subf = call->getCalledFunction();
					assert(subf != NULL);
					StringRef func_name = subf->getName();
				
					if (func_name.startswith("record_") ||
								subf->isDeclaration() ||
								subf->isIntrinsic()) {
							// ignore
						break;	
					}
					else if (func_name.startswith("llvm.memset")) {
						Panda__LogEntry* ple = ple_vector[cursor_idx];
						assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_STORE);

						t.ple = ple;
						t.inst = i; 
						t.func = f; 

						aligned_block.push_back(t);

					}
					else if (func_name.startswith("llvm.memcpy")) {
						Panda__LogEntry* ple = ple_vector[cursor_idx+1];
						assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_STORE);
						ple = ple_vector[cursor_idx];
						assert(ple->llvmentry->type = FunctionCode::FUNC_CODE_INST_LOAD);
						
						t.ple = ple;
						t.inst = i; 
						t.func = f; 

						aligned_block.push_back(t);
					}
					else {
						// descend into function
						cursor_idx = align_function(aligned_block, subf, ple_vector, cursor_idx);
					
						Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
						*ple = PANDA__LLVMENTRY__INIT;
						Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
						new_dyn.llvmentry = ple; // sentinel

						t.func = f; t.inst = i; t.ple = &new_dyn;
						aligned_block.push_back(t);
					}
				}
				default:
					printf("fell through!\n");

					Panda__LLVMEntry *ple = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
					*ple = PANDA__LLVMENTRY__INIT;
					Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
					new_dyn.llvmentry = ple; // sentinel

					t.func = f; t.inst = i; t.ple = &new_dyn;
					aligned_block.push_back(t);
					break;

			}
		}
	}		
    return cursor_idx;
	// Iterate every instruction to find its uses and its definition
	// if one of the definitions is in the working list (which contains initial criterion)
	// update working list with the uses 

	//update worklist 
	/*for (auto it )*/
	
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
	pandalog_open_read_bwd(llvm_trace_fname);
	
	Panda__LogEntry *ple;
	// read all pandalog entritb->llvm_function. 
	//while ((ple = pandalog_read_entry()) != NULL){
		//printf("ple llvm entry %p", ple->llvmentry);
		//ple_vector.push_back(ple); 
	//}
    
	/*uint64_t max_idx = ple_vector.size()-1;*/
	/*uint64_t ple_idx = 0;*/
	/*uint64_t ple_idx = ple_vector.size()-1;*/

	int cursor_idx = 0;
	std::vector<Panda__LogEntry*> ple_vector; 	
	// Process by the function? I'll just do the same thing as dynslice1.cpp for now. 
	while ((ple = pandalog_read_entry()) != NULL) {
		// while we haven't reached beginning of file yet 
		char namebuf[128];
		/*printf("ple_idx %lu\n", ple_idx);*/
		/*ple = pandalog_read_entry();*/
		pprint_ple(ple);
		ple_vector.push_back(ple);

		if (ple->llvmentry != NULL && ple->llvmentry->type == FunctionCode::LLVM_FN && ple->llvmentry->tb_num){
			if (ple->llvmentry->tb_num == 0) {
				//ple_idx++; 
				continue;
			}
			sprintf(namebuf, "tcg-llvm-tb-%lu-%lx", ple->llvmentry->tb_num, ple->pc);
			printf("********** %s **********\n", namebuf);
			Function *f = mod->getFunction(namebuf);
			
			assert(f != NULL);
			
			std::vector<traceEntry> aligned_block;
			cursor_idx = align_function(aligned_block, f, ple_vector, cursor_idx);
			// now, align trace and llvm bitcode by creating traceEntries with dynamic info filled in 
			// maybe i can do this lazily...
			
			//slice_trace(aligned_block, work);

			//printf("Working set: ");
			//print_set(work);
			//// CLear ple_vector for next block
			//ple_vector.clear();
		}
		/*ple_idx++;*/
	}
	
	//slice_trace(ple_vector);

	pandalog_close();
	return 0;
}


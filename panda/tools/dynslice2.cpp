
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
#include "panda/addr.h"
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
#include "llvm/Support/Regex.h"

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

typedef std::pair<SliceVarType,uint64_t> SliceVar;

int ret_ctr = 0;

//add stuff to this as needed
struct traceEntry {
    llvm::Function *func;
    llvm::Instruction *inst;
    
    Panda__LogEntry* ple;
    Panda__LogEntry* ple2;
    //special snowflake?
    // memcpy may need another logentry 
};

std::set<SliceVar> workList; 
std::vector<traceEntry> traceEntries;

bool debug = false;

Panda__LogEntry* cursor; 

void print_insn(Instruction *insn) {
    std::string s;
    raw_string_ostream ss(s);
    insn->print(ss);
    ss.flush();
    printf("%s\n", ss.str().c_str());
    return;
}

std::string SliceVarStr(const SliceVar &s) {
    char output[128] = {};

    switch (s.first) {
        case LLVM:
            sprintf(output, "LLVM_%lx", s.second);
            break;
        case MEM:
            sprintf(output, "MEM_%lx", s.second);
            break;
        case HOST:
            sprintf(output, "HOST_%lx", s.second);
            break;
        case REG:
            sprintf(output, "REG_%lx", s.second);
            break;
        case SPEC:
            sprintf(output, "SPEC_%lx", s.second);
            break;
        case FRET:
            sprintf(output, "RET_%lx", s.second);
            break;
        default:
            assert (false && "No such SliceVarType");
    }

    return output;
}


void print_set(std::set<SliceVar> &s) {
    printf("{");
    for (const SliceVar &w : s) printf(" %s", SliceVarStr(w).c_str());
    printf(" }\n");
}

void pprint_llvmentry(Panda__LogEntry *ple){
    printf("\tllvmEntry: {\n");
    printf("\t\ttype = %s\n", functionCodeStrings[static_cast<FunctionCode>(ple->llvmentry->type)].c_str()); 
    printf("\t\taddress = %lx\n", ple->llvmentry->address);
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

void insertAddr(std::set<SliceVar> &sliceSet, SliceVarType type, uint64_t dyn_addr, int numBytes){
    switch (type){
        case REG:
            sliceSet.insert(std::make_pair(REG, dyn_addr));
            break;
        case MEM:
            for (int off = 0; off < numBytes; off++){
                sliceSet.insert(std::make_pair(MEM, dyn_addr+off));
            }
            break;
        case IGNORE:
        default:
            printf("Warning: unhandled address entry type %d\n", type);
            break;
    }
}

void insertValue(std::set<SliceVar> &sliceSet, Value* v){
    if(!isa<Constant>(v)){
        sliceSet.insert(std::make_pair(LLVM, uint64_t(v)));
    }
}

void get_usedefs_Store(traceEntry &t,
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    StoreInst* SI = dyn_cast<StoreInst>(t.inst);
    assert(t.ple->llvmentry->address);
    assert(t.ple->llvmentry->num_bytes);
    assert(t.ple->llvmentry->addr_type);

    insertAddr(uses, static_cast<SliceVarType>(t.ple->llvmentry->addr_type), t.ple->llvmentry->address, t.ple->llvmentry->num_bytes);
    
};

void get_usedefs_Load(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    LoadInst* LI = dyn_cast<LoadInst>(t.inst);
    assert(t.ple->llvmentry->address);
    assert(t.ple->llvmentry->num_bytes);
    assert(t.ple->llvmentry->addr_type);

    // Add the memory address to the uses list. 
    // Giri goes back and searches for the stores before this load. Maybe that's better? 

     // Whereas moyix's stuff differentiates addresses and registers when storing in use list
     // I'll do what moyix does for now....

    // inserts dynamic address into use list
    insertAddr(uses, static_cast<SliceVarType>(t.ple->llvmentry->addr_type), t.ple->llvmentry->address, t.ple->llvmentry->num_bytes);

    insertValue(uses, LI);

    insertValue(defines, t.inst);
};

void get_usedefs_Call(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    CallInst* c = dyn_cast<CallInst>(t.inst);

    Function *subf = c->getCalledFunction();
    StringRef func_name = subf->getName();
    if (func_name.startswith("__ld")) {
        char sz_c = func_name[4];
        int size = -1;
        switch(sz_c) {
            case 'q': size = 8; break;
            case 'l': size = 4; break;
            case 'w': size = 2; break;
            case 'b': size = 1; break;
            default: assert(false && "Invalid size in call to load");
        }
        
        insertAddr(uses, MEM, t.ple->llvmentry->address, size);

        Value *load_addr = c->getArgOperand(0);
        insertValue(uses, load_addr);
        insertValue(defines, t.inst);
    }
    //TODO: Fix
    else if (func_name.startswith("__st")) {
        char sz_c = func_name[4];
        int size = -1;
        switch(sz_c) {
            case 'q': size = 8; break;
            case 'l': size = 4; break;
            case 'w': size = 2; break;
            case 'b': size = 1; break;
            default: assert(false && "Invalid size in call to store");
        }
        
        insertAddr(defines, MEM, t.ple->llvmentry->address, size);
        
        Value *store_addr = c->getArgOperand(0);
        Value *store_val  = c->getArgOperand(1);
        insertValue(uses, store_addr);
        insertValue(uses, store_val);
    }
    else if (func_name.startswith("llvm.memcpy")) {

        // Get memcpy size
        int bytes = 0;
        Value *bytes_ir = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Load first
        insertAddr(uses, static_cast<SliceVarType>(t.ple->llvmentry->addr_type), t.ple->llvmentry->address, bytes);

        // Now store
        insertAddr(defines, static_cast<SliceVarType>(t.ple->llvmentry->addr_type), t.ple->llvmentry->address, bytes);

        // Src/Dst pointers
        insertValue(uses, c->getArgOperand(0));
        insertValue(uses, c->getArgOperand(1));
        
    }
    else if (func_name.startswith("llvm.memset")) {

        int bytes = 0;
        Value *bytes_ir  = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Now store
        insertAddr(defines, static_cast<SliceVarType>(t.ple->llvmentry->addr_type), t.ple->llvmentry->address, bytes);

        // Dst pointer
        insertValue(uses, c->getArgOperand(0));

        // Value (if not constant)
        insertValue(uses, c->getArgOperand(1));
    }
    else if (func_name.equals("helper_inb") ||
             func_name.equals("helper_inw") ||
             func_name.equals("helper_inl")) {
        insertValue(uses, c->getArgOperand(0));
        insertValue(defines, c);
    }
    else if (func_name.equals("helper_outb") ||
             func_name.equals("helper_outw") ||
             func_name.equals("helper_outl")) {
        // We don't have any model of port I/O, so
        // we just ignore this one
    }
    else {
        // call to some helper
        if (!c->getType()->isVoidTy()) {
            insertValue(defines, c);
        }
        // Uses the return value of that function.
        // Note that it does *not* use the arguments -- these will
        // get included automatically if they're needed to compute
    
    // the return value.
        uses.insert(std::make_pair(FRET, ret_ctr));
    }
    return;
};

void get_usedefs_Ret(traceEntry &t, 
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defines){
    
    ReturnInst *r = cast<ReturnInst>(t.inst);
    Value *v = r->getReturnValue();
    if (v != NULL) insertValue(uses, v);

    defines.insert(std::make_pair(FRET, ret_ctr++));
};

void get_usedefs_PHI(traceEntry &t, 
    std::set<SliceVar> &uses, 
    std::set<SliceVar> &defines){
    assert(t.ple->llvmentry->phi_index);
    PHINode *p = cast<PHINode>(t.inst);
    
    Value *v = p->getIncomingValue(t.ple->llvmentry->phi_index);
    insertValue(uses, v);
    insertValue(defines, t.inst); 
};

void get_usedefs_Select(traceEntry &t, 
std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    SelectInst *si = cast<SelectInst>(t.inst);
    assert(t.ple->llvmentry->condition);
    
    if (t.ple->llvmentry->condition){
        // if condition is true, choose the first select val
       insertValue(uses, si->getTrueValue()); 
    } else {
        // if condition is true, choose the first select val
       insertValue(uses, si->getFalseValue()); 
    }
};

void get_usedefs_Br(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    BranchInst *bi= dyn_cast<BranchInst>(t.inst);

    if (bi->isConditional()){
        insertValue(uses, bi->getCondition());
    }
}

void get_usedefs_Switch(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    SwitchInst *si = dyn_cast<SwitchInst>(t.inst);
    insertValue(uses, si->getCondition());
}

void get_usedefs_default(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    // by default, add all operands to uselist
    for (User::op_iterator op = t.inst->op_begin(); op != t.inst->op_end(); op++){
        Value *v = *op;
        
        //XXX: May no longer need to check for BB anymore, since we handle br and switch separately now. 
        if (!dyn_cast<BasicBlock>(v)){
            insertValue(uses, v);
        }
    }
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
            get_usedefs_Br(t, uses, defs);
            return;
        case Instruction::Switch:
            get_usedefs_Switch(t, uses, defs);
            return;
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
void slice_trace(std::vector<traceEntry> &aligned_block, std::set<SliceVar> &worklist){
        
    printf("in slice trace\n");
    std::cout << aligned_block.size() << "\n";
    for (std::vector<traceEntry>::iterator i = aligned_block.begin() ; i != aligned_block.end(); ++i) {
        std::set<SliceVar> uses, defs;
        get_uses_and_defs(*i, uses, defs);

        print_insn(i->inst);

        printf("DEBUG: %lu defs, %lu uses\n", defs.size(), uses.size());
         printf("DEFS: ");
        print_set(defs);
        printf("USES: ");
        print_set(uses);
        
        //update worklist
        
        for (std::set<SliceVar>::iterator it = uses.begin(); it != uses.end(); it++){
            
            
        }

        

    }
    
}

bool in_exception = false;

int align_function(std::vector<traceEntry> &aligned_block, llvm::Function* f, std::vector<Panda__LogEntry*> ple_vector, int cursor_idx){
    
    printf("f getname %s", f->getName().str().c_str());

    /*cursor_idx = 0;*/
    BasicBlock &entry = f->getEntryBlock();
    BasicBlock *nextBlock = &entry;
    bool has_successor = true;
    while (has_successor) {
        has_successor = false;
        
        for (BasicBlock::iterator i = nextBlock->begin(), e = nextBlock->end(); i != e; ++i) {
            traceEntry t = {};
            if(in_exception) return cursor_idx;
            Panda__LogEntry* ple;
            if (cursor_idx >= ple_vector.size()){
                ple = NULL;
            } else{
                ple = ple_vector[cursor_idx];
                //pprint_ple(ple);
            }

            // Peek at the next thing in the log. If it's an exception, no point
            // processing anything further, since we know there can be no dynamic
            // values before the exception.
            if (ple && ple->llvmentry->type == LLVM_EXCEPTION) {
                printf("Found exception, will not finish this function.\n");
                in_exception = true;
                cursor_idx++;
                return cursor_idx;
            }

            switch (i->getOpcode()){
                case Instruction::Load: {
                    // get the value from the trace 
                    //
                    assert (ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_LOAD);
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

                    assert (ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_STORE);
                    t.ple = ple;
                    t.inst = i;
                    t.func = f;

                    cursor_idx++;
                    aligned_block.push_back(t);
                    break;
                }
                case Instruction::Br: {

                    //Check that this entry is a BR entry
                    assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_BR);

                    Panda__LLVMEntry *llvmentry = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
                    *llvmentry = PANDA__LLVMENTRY__INIT;
                    Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
                    new_dyn.llvmentry = llvmentry; // sentinel

                    t.ple = &new_dyn;
                    t.inst = i;
                    t.func = f;

                    //update next block to examine
                    has_successor = true;
                    BranchInst *b = cast<BranchInst>(&*i);
                    nextBlock = b->getSuccessor(!(ple->llvmentry->condition));
                    //nextBlock->dump();

                    aligned_block.push_back(t);
                    
                    Panda__LogEntry *bbPle = ple_vector[cursor_idx+1];
                    assert(bbPle && bbPle->llvmentry->type == FunctionCode::BB);

                    cursor_idx+=2;
                    break;
                }
                case Instruction::Switch: {
                    //Check that current entry is a startBB entry
                    assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_SWITCH);
                    
                    Panda__LLVMEntry *llvmentry = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
                    *llvmentry = PANDA__LLVMENTRY__INIT;
                    Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
                    new_dyn.llvmentry = llvmentry; // sentinel
                    t.ple = &new_dyn;
                    t.inst = i;
                    t.func = f;
                    
                    aligned_block.push_back(t);

                    //update next block to examine
                    SwitchInst *s = cast<SwitchInst>(&*i);
                    unsigned width = s->getCondition()->getType()->getPrimitiveSizeInBits();
                    IntegerType *intType = IntegerType::get(getGlobalContext(), width);
                    ConstantInt *caseVal = ConstantInt::get(intType, ple->llvmentry->condition);
                    
                    has_successor = true;
                    SwitchInst::CaseIt caseIndex = s->findCaseValue(caseVal);
                    nextBlock = s->getSuccessor(caseIndex.getSuccessorIndex());
                    //nextBlock->dump();

                    Panda__LogEntry *bbPle = ple_vector[cursor_idx+1];
                    assert(bbPle && bbPle->llvmentry->type == FunctionCode::BB);
                    
                    cursor_idx+=2;
                    break;
                }
                case Instruction::PHI: {
                    
                    // We don't actually have a dynamic log entry here, but for
                    // convenience we do want to know which basic block we just
                    // came from. So we peek at the previous non-PHI thing in
                    // our trace, which should be the predecessor basic block
                    // to this PHI
                    PHINode *p = cast<PHINode>(&*i);
                    Panda__LLVMEntry *llvmentry = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
                    *llvmentry = PANDA__LLVMENTRY__INIT;
                    llvmentry->has_phi_index = 1;
                    llvmentry->phi_index = -1;
                    Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
                    new_dyn.llvmentry = llvmentry; // sentinel
                    // Find the last non-PHI instruction
                    // Search from Reverse beginning (most recent traceEntry) 
                    for (auto sit = aligned_block.rbegin(); sit != aligned_block.rend(); sit++) {
                        if (sit->inst->getOpcode() != Instruction::PHI) {
                            llvmentry->phi_index = p->getBasicBlockIndex(sit->inst->getParent());
                            break;
                        }
                    }
                    t.func = f; t.inst = i;
                    t.ple = &new_dyn;
                    aligned_block.push_back(t);
                    //cursor_idx++;
                    break;
                }
                case Instruction::Select: {
                    assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_SELECT);

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
                
                    if (func_name.startswith("record")){
                            // ignore
                        printf("ignoring record func in align\n");
                    } 
                    else if (Regex("helper_[lb]e_ld.*_mmu_panda").match(func_name)) {
                        assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_LOAD);
                        
                        t.ple = ple;
                        t.inst = i; 
                        t.func = f;

                        aligned_block.push_back(t);
                        cursor_idx++;
                    } 
                    else if (Regex("helper_[lb]e_st.*_mmu_panda").match(func_name)) {
                        assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_STORE);

                        t.ple = ple;
                        t.inst = i; 
                        t.func = f;
                          
                        aligned_block.push_back(t);
                        cursor_idx++;

                    } 
                    else if (subf->isDeclaration()) {
                        // we don't have any code for this function
                        // there's no log entry either, so don't increment cursor_idx
                        
                    } 
                    else if (func_name.startswith("llvm.memset")) {
                        assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_STORE);

                        t.ple = ple;
                        t.inst = i; 
                        t.func = f; 

                        aligned_block.push_back(t);
                        cursor_idx++;
                    }
                    else if (func_name.startswith("llvm.memcpy")) {
                        assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_LOAD);
                        Panda__LogEntry *storePle = ple_vector[cursor_idx+1];
                        assert(storePle && storePle->llvmentry->type == FunctionCode::FUNC_CODE_INST_STORE);
                        
                        t.ple = ple;
                        t.ple2 = storePle;
                        t.inst = i; 
                        t.func = f; 

                        aligned_block.push_back(t);
                        cursor_idx += 2;
                    }
                    else if (subf->isIntrinsic()){
                        printf("Unhandled intrinsic\n");
                    }
                    else {
                        // descend into function
                        assert(ple && ple->llvmentry->type == FunctionCode::FUNC_CODE_INST_CALL);
                        
                        Panda__LogEntry *bbPle = ple_vector[cursor_idx+1];
                        assert(bbPle && bbPle->llvmentry->type == FunctionCode::BB);
                        
                        printf("descending into function, cursor_idx= %d\n", cursor_idx+2);
                        cursor_idx = align_function(aligned_block, subf, ple_vector, cursor_idx+2);
                        printf("Returned from descend, cursor_idx= %d\n", cursor_idx);
                    
                        Panda__LLVMEntry *llvmentry = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
                        *llvmentry = PANDA__LLVMENTRY__INIT;
                        Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
                        new_dyn.llvmentry = llvmentry; // sentinel

                        t.func = f; t.inst = i; t.ple = &new_dyn;
                        aligned_block.push_back(t);
                    }
                }
                default:
                    //printf("fell through!\n");
                    /*print_insn(i);*/

                    Panda__LLVMEntry *llvmentry = (Panda__LLVMEntry *)(malloc(sizeof(Panda__LLVMEntry)));
                    *llvmentry = PANDA__LLVMENTRY__INIT;
                    Panda__LogEntry new_dyn = PANDA__LOG_ENTRY__INIT;
                    new_dyn.llvmentry = llvmentry; // sentinel

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
    SliceVarType typ = LLVM;
    uint64_t addr = 0;
    char *addrstr = NULL;

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


void usage(char *prog) {
   fprintf(stderr, "Usage: %s [OPTIONS] <llvm_mod> <dynlog> <criterion> [<criterion> ...]\n",
           prog);
   fprintf(stderr, "Options:\n"
           "  -b                : include branch conditions in slice\n"
           "  -d                : enable debug output\n"
           "  -n NUM -p PC      : start slicing from TB NUM-PC\n"
           "  -o OUTPUT         : save slice results to OUTPUT\n"
           "  <llvm_mod>        : the LLVM bitcode module\n"
           "  <dynlog>          : the pandalog trace file\n"
           "  <criterion> ...   : the slicing criteria, i.e., what to slice on\n"
           "                      Use REG_[N] for registers, MEM_[PADDR] for memory\n"
          );
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
     
    while ((opt = getopt(argc, argv, "vbdn:p:o:")) != -1) {
        switch (opt) {
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
        case 'o':
            output = optarg;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    char *llvm_mod_fname = argv[optind];
    char *llvm_trace_fname = argv[optind+1];

    // Maintain a working set 
    // if mem, search for last occurrence of that physical address  

    llvm::LLVMContext &ctx = llvm::getGlobalContext();
    llvm::SMDiagnostic err;
    llvm::Module *mod = llvm::ParseIRFile(llvm_mod_fname, err, ctx);

    // read trace into memory

    // Add the slicing criteria
    for (int i = optind + 2; i < argc; i++) {
        workList.insert(VarFromStr(argv[i]));
    }

    if (output == NULL) {
        output = "slice_report.bin";
        fprintf(stderr, "Note: no output file provided. Will save results to '%s'\n", output);
    }

    printf("Slicing trace\n");
    pandalog_open_read_bwd(llvm_trace_fname);
    
    Panda__LogEntry *ple;

    //int i = 0;
    //while ((ple = pandalog_read_entry()) != NULL){
        //if(i <= 7 || i >= 2031870){
            //pprint_ple(ple);
        //}
        //i++;
    //}
    //printf("i %d\n", i);
    
    /*uint64_t max_idx = ple_vector.size()-1;*/
    /*uint64_t ple_idx = 0;*/
    /*uint64_t ple_idx = ple_vector.size()-1;*/

    std::vector<Panda__LogEntry*> ple_vector;   
    std::vector<traceEntry> aligned_block;
    // Process by the function? I'll just do the same thing as dynslice1.cpp for now. 
    while ((ple = pandalog_read_entry()) != NULL) {
        // while we haven't reached beginning of file yet 
        char namebuf[128];
        /*printf("ple_idx %lu\n", ple_idx);*/
        /*ple = pandalog_read_entry();*/
        //pprint_ple(ple);
        ple_vector.push_back(ple);

        if (ple->llvmentry != NULL && ple->llvmentry->type == FunctionCode::LLVM_FN && ple->llvmentry->tb_num){
            if (ple->llvmentry->tb_num == 0) {
                //ple_idx++; 
                continue;
            }
            int cursor_idx = 0;
            sprintf(namebuf, "tcg-llvm-tb-%lu-%lx", ple->llvmentry->tb_num, ple->pc);
            printf("********** %s **********\n", namebuf);
            Function *f = mod->getFunction(namebuf);
            
            assert(f != NULL);
            
            aligned_block.clear();
            std::reverse(ple_vector.begin(), ple_vector.end());
            //Skip over first two entries, LLVM_FN and BB
            assert(ple_vector[0]->llvmentry->type == FunctionCode::LLVM_FN && ple_vector[1]->llvmentry->type == FunctionCode::BB);
            ple_vector.erase(ple_vector.begin(), ple_vector.begin()+2);
            cursor_idx = align_function(aligned_block, f, ple_vector, cursor_idx);
            // now, align trace and llvm bitcode by creating traceEntries with dynamic info filled in 
            // maybe i can do this lazily...
            
            /*slice_trace(aligned_block, workList);*/

            /*printf("Working set: ");*/
            /*print_set(workList);*/
            //// CLear ple_vector for next block
            ple_vector.clear();
        }
        /*ple_idx++;*/
    }
    
    //slice_trace(ple_vector);

    pandalog_close();
    return 0;
}


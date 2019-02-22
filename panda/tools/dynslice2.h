#ifndef DYNSLICE2_H
#define DYNSLICE2_H

#include <vector>
#include <map>
#include <set>
#include <stack>
#include <bitset>

#include "panda/plugins/llvm_trace2/functionCode.h"
#include "panda/plog-cc.hpp"

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


//add stuff to this as needed
struct traceEntry {
    uint16_t bb_num;
    int inst_index;
    llvm::Function *func;
    llvm::Instruction *inst;
    
    panda::LogEntry* ple = NULL;
    panda::LogEntry* ple2 = NULL;
    //special snowflake?
    // memcpy may need another logentry 

    std::string target_asm;

    bool operator==(const traceEntry& other) const 
    {
        return (inst == other.inst);
    }
};


int align_function(std::vector<traceEntry> &aligned_block, llvm::Function* f, std::vector<panda::LogEntry*>& ple_vector, int cursor_idx);

#endif
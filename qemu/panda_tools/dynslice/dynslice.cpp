#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/raw_ostream.h"

#include "tubtf.h"
#include "panda_memlog.h"

using namespace llvm;

#define ASSERT(left,operator,right) { if(!((left) operator (right))){ errs() << "ASSERT FAILED: " << #left << #operator << #right << " @ " << __FILE__ << " (" << __LINE__ << "). " << #left << "=" << (left) << "; " << #right << "=" << (right) << "\n"; } assert(0); }

std::string TubtfEITypeStr[TUBTFE_LLVM_EXCEPTION+1] = {
    "TUBTFE_USE",
    "TUBTFE_DEF",
    "TUBTFE_TJMP",
    "TUBTFE_TTEST",
    "TUBTFE_TCMP",
    "TUBTFE_TLDA",
    "TUBTFE_TLDV",
    "TUBTFE_TSTA",
    "TUBTFE_TSTV",
    "TUBTFE_TFNA_VAL",
    "TUBTFE_TFNA_PTR",
    "TUBTFE_TFNA_STR",
    "TUBTFE_TFNA_ECX",
    "TUBTFE_TFNA_EDX",
    "TUBTFE_TVE_JMP",
    "TUBTFE_TVE_TEST_T0",
    "TUBTFE_TVE_TEST_T1",
    "TUBTFE_TVE_CMP_T0",
    "TUBTFE_TVE_CMP_T1",
    "TUBTFE_TVE_LDA",
    "TUBTFE_TVE_LDV",
    "TUBTFE_TVE_STA",
    "TUBTFE_TVE_STV",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "TUBTFE_LLVM_FN",
    "TUBTFE_LLVM_DV_LOAD",
    "TUBTFE_LLVM_DV_STORE",
    "TUBTFE_LLVM_DV_BRANCH",
    "TUBTFE_LLVM_DV_SELECT",
    "TUBTFE_LLVM_DV_SWITCH",
    "TUBTFE_LLVM_EXCEPTION",
};

struct __attribute__((packed)) TUBTEntry {
    uint64_t asid;
    uint64_t pc;
    uint64_t type;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
};

bool debug = false;
void dump_tubt(TUBTEntry *row) {
    printf("%x %x %s %x %x %x %x\n", row->asid, row->pc, TubtfEITypeStr[row->type].c_str(), row->arg1, row->arg2, row->arg3, row->arg4);
}

TUBTEntry * process_func(Function *f, TUBTEntry *dynvals) {
    TUBTEntry *cursor = dynvals;
    BasicBlock &entry = f->getEntryBlock();
    BasicBlock *block = &entry;
    bool have_successor = true;
    while (have_successor) {
        have_successor = false;
        for (BasicBlock::iterator i = block->begin(), e = block->end(); i != e; ++i) {
            if (debug) errs() << *i << "\n";
            switch (i->getOpcode()) {
                case Instruction::Load: {
                    assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                    LoadInst *l = cast<LoadInst>(&*i);
                    if (debug) dump_tubt(cursor);
                    cursor++;
                    break;
                }
                case Instruction::Store: {
                    StoreInst *s = cast<StoreInst>(&*i);
                    if (!s->isVolatile()) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                    }
                    break;
                }
                case Instruction::Br: {
                    assert(cursor->type == TUBTFE_LLVM_DV_BRANCH);
                    BranchInst *b = cast<BranchInst>(&*i);
                    block = b->getSuccessor(cursor->arg1);
                    if (debug) dump_tubt(cursor);
                    cursor++;
                    have_successor = true;
                    break;
                }
                case Instruction::Switch: {
                    assert(cursor->type == TUBTFE_LLVM_DV_SWITCH);
                    SwitchInst *s = cast<SwitchInst>(&*i);
                    unsigned width = s->getCondition()->getType()->getPrimitiveSizeInBits();
                    IntegerType *intType = IntegerType::get(getGlobalContext(), width);
                    ConstantInt *caseVal = ConstantInt::get(intType, cursor->arg1);
                    SwitchInst::CaseIt caseIndex = s->findCaseValue(caseVal);
                    block = s->getSuccessor(caseIndex.getSuccessorIndex());
                    if (debug) dump_tubt(cursor);
                    cursor++;
                    have_successor = true;
                    break;
                }
                case Instruction::Select: {
                    assert(cursor->type == TUBTFE_LLVM_DV_SELECT);
                    SelectInst *s = cast<SelectInst>(&*i);
                    if (debug) dump_tubt(cursor);
                    cursor++;
                    break;
                }
                case Instruction::Call: {
                    CallInst *c =  cast<CallInst>(&*i);
                    Function *subf = c->getCalledFunction();
                    assert(subf != NULL);
                    StringRef func_name = subf->getName();
                    if (func_name.startswith("__ld")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                    }
                    else if (func_name.startswith("__st")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memcpy")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memset")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        cursor++;
                    }
                    else if (func_name.equals("log_dynval") ||
                             subf->isDeclaration() ||
                             subf->isIntrinsic()) {
                        // ignore
                    }
                    else {
                        // descend
                        cursor = process_func(subf, cursor);
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }
    return cursor;
}

int main(int argc, char **argv) {
    // mmap the dynamic log
    struct stat st;
    if(argc < 3) {
        fprintf(stderr, "usage: %s <llvm_mod> <dynlog>\n", argv[0]);
        return 1;
    }
    if (stat(argv[2], &st) != 0) {
        perror("stat");
        return 1;
    }
    uint64_t num_rows = (st.st_size - 20) / sizeof(TUBTEntry);
    int fd = open(argv[2], O_RDWR|O_LARGEFILE);
    uint8_t *mapping = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    TUBTEntry *rows = (TUBTEntry *)(mapping + 20);
    TUBTEntry *endp = rows + num_rows;

    LLVMContext &ctx = getGlobalContext();

    // Load the bitcode...
    SMDiagnostic err;

    Module *mod = ParseIRFile(argv[1], err, ctx);

    TUBTEntry *cursor = rows;
    if (argc == 5) {
        // debug: allow seeking to a specific tb
        unsigned long num = strtoul(argv[3], NULL, 10);
        unsigned long pc = strtoul(argv[4], NULL, 16);
        debug = true;
        while (!(cursor->type == TUBTFE_LLVM_FN && cursor->pc == pc && cursor->arg1 == num)) cursor++;
        TUBTEntry *dbgcurs = cursor + 1;
        while (dbgcurs->type != TUBTFE_LLVM_FN) dump_tubt(dbgcurs++);
    }

    while (cursor != endp) {
        assert (cursor->type == TUBTFE_LLVM_FN);
        char namebuf[128];
        sprintf(namebuf, "tcg-llvm-tb-%d-%x", cursor->arg1, cursor->pc);
        printf("%s\n", namebuf);
        Function *f = mod->getFunction(namebuf);
        assert(f != NULL);
        cursor++; // Don't include the function entry
        cursor = process_func(f, cursor);
    }
    
    return 0;
}

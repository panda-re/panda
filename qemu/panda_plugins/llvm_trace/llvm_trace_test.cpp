/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

/*
 * This test recreates an entire trace (including all helper functions) in LLVM
 * format, and ensures that dynamic values in the log line up with their
 * expected location in the bitcode.
 */

#include "stdio.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm_trace_test.h"
#include "panda_memlog.h"

using namespace llvm;

FILE *flog;          // Function log
FILE *dlog;          // Dynamic value log
bool except;         // Exception flag, global regardless of generated code or
                     // helper function

/***
 *** TestInstVisitor
 ***/

void TestInstVisitor::visitLoadInst(LoadInst &I){
    if (except){
        return;
    }

    //printf("load\n");
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    if (entry.entrytype == EXCEPTIONENTRY){
        except = true;
        return;
    }
    assert((entry.entrytype == ADDRENTRY)
        && (entry.entry.memaccess.op == LOAD));
}

void TestInstVisitor::visitStoreInst(StoreInst &I){
    if (I.isVolatile() || except){
        return; // These are part of the runtime system that we don't log
    }

    //printf("store\n");
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    if (entry.entrytype == EXCEPTIONENTRY){
        except = true;
        return;
    }
    assert((entry.entrytype == ADDRENTRY)
        && (entry.entry.memaccess.op == STORE));
}

void TestInstVisitor::visitBranchInst(BranchInst &I){
    if (except){
        return;
    }

    //printf("branch\n");
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    if (entry.entrytype == EXCEPTIONENTRY){
        except = true;
        return;
    }
    assert(entry.entrytype == BRANCHENTRY);
    TFP->setNextBB(I.getSuccessor(entry.entry.branch.br));
}

void TestInstVisitor::visitReturnInst(ReturnInst &I){
    //printf("ret\n");
    TFP->setRetFlag(true);
}

/*
 * A lot of helper functions end with unreachable instructions, so we treat them
 * like return instructions.
 */
void TestInstVisitor::visitUnreachable(UnreachableInst &I){
    //printf("ret\n");
    TFP->setRetFlag(true);
}

void TestInstVisitor::visitSelectInst(SelectInst &I){
    if (except){
        return;
    }

    //printf("select\n");
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    if (entry.entrytype == EXCEPTIONENTRY){
        except = true;
        return;
    }
    assert(entry.entrytype == SELECTENTRY);
}

void TestInstVisitor::visitCallInst(CallInst &I){
    if (except){
        return;
    }

    if ((I.getCalledFunction()->getName() == "__ldb_mmu_panda")
        || (I.getCalledFunction()->getName() == "__ldl_mmu_panda")
        || (I.getCalledFunction()->getName() == "__ldw_mmu_panda")
        || (I.getCalledFunction()->getName() == "__ldq_mmu_panda")){

        DynValEntry entry;
        size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
        if (entry.entrytype == EXCEPTIONENTRY){
            except = true;
            return;
        }
        assert((entry.entrytype == ADDRENTRY)
            && (entry.entry.memaccess.op == LOAD));
        return;
    }
    if ((I.getCalledFunction()->getName() == "__stb_mmu_panda")
        || (I.getCalledFunction()->getName() == "__stl_mmu_panda")
        || (I.getCalledFunction()->getName() == "__stw_mmu_panda")
        || (I.getCalledFunction()->getName() == "__stq_mmu_panda")){

        DynValEntry entry;
        size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
        if (entry.entrytype == EXCEPTIONENTRY){
            except = true;
            return;
        }
        assert((entry.entrytype == ADDRENTRY)
            && (entry.entry.memaccess.op == STORE));
        return;
    }

    if ((I.getCalledFunction()->getName() == "log_dynval")
        || (I.getCalledFunction()->isDeclaration())
        || (I.getCalledFunction()->isIntrinsic())){
        return;
    }

    //printf("call %s\n", I.getCalledFunction()->getName().str().c_str());
    TestFunctionPass *newTFP = new TestFunctionPass();
    newTFP->runOnFunction(*I.getCalledFunction());
    delete newTFP;
}

void TestInstVisitor::visitSwitchInst(SwitchInst &I){
    if (except){
        return;
    }

    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    if (entry.entrytype == EXCEPTIONENTRY){
        except = true;
        return;
    }
    assert(entry.entrytype == SWITCHENTRY);
    //printf("switch %d\n", entry.entry.switchstmt.cond);
    IntegerType *intType = IntegerType::get(getGlobalContext(), sizeof(int)*8);
    ConstantInt *caseVal =
        ConstantInt::get(intType, entry.entry.switchstmt.cond);
    SwitchInst::CaseIt caseIndex = I.findCaseValue(caseVal);
    TFP->setNextBB(I.getSuccessor(caseIndex.getSuccessorIndex()));
}

/***
 *** TestFunctionPass
 ***/

void TestFunctionPass::setNextBB(BasicBlock *bb){
    next_bb = bb;
}

BasicBlock *TestFunctionPass::getNextBB(){
    return next_bb;
}

void TestFunctionPass::setRetFlag(bool flag){
    retFlag = flag;
}

bool TestFunctionPass::getRetFlag(){
    return retFlag;
}

bool TestFunctionPass::runOnFunction(Function &F){
    retFlag = false;
    except = false;

    // Process function starting with the entry basic block
    Function::iterator bb = F.begin();
    TIV->visit(bb);

    // If a function has multiple basic blocks, process them until we reach ret
    if (F.size() > 1){
        while (!retFlag && !except){ // Continue until we reach a return
                                     // instruction or exception
            //printf("visiting BB %s\n", next_bb->getName().str().c_str());
            TIV->visit(next_bb);
        }
    }

    return false; // Doesn't modify the function
}

char TestFunctionPass::ID = 0;
static RegisterPass<TestFunctionPass> Y("Test", "Test for a valid LLVM trace");

FunctionPass *createTestFunctionPass(){
    return new TestFunctionPass();
}

namespace {
    cl::opt<std::string> LogDir("d", cl::desc("directory containing logs"),
        cl::Required);
}

int main(int argc, char **argv){
    cl::ParseCommandLineOptions(argc, argv, "llvm_trace_test\n");

    char directory[250];
    strncpy(directory, LogDir.c_str(), 250);
    int len = strlen(directory);
    if (len > 230){
        printf("Directory name too long\n");
        exit(1);
    }

    LLVMContext &Context = getGlobalContext();

    // Load the bitcode...
    SMDiagnostic Err;
    Module *Mod = ParseIRFile(strncat(directory, "/llvm-mod.bc", 12), Err,
        Context);
    if (!Mod) {
        Err.print(argv[0], errs());
        exit(1);
    }

    // Load dynamic log
    directory[len] = '\0';
    dlog = fopen(strncat(directory, "/llvm-memlog.log", 16), "r");
    if (!dlog){
        printf("Could not find log of dynamic values in specified directory\n");
        exit(1);
    }

    // Load function log
    directory[len] = '\0';
    flog = fopen(strncat(directory, "/llvm-functions.log", 19), "r");
    if (!flog){
        printf("Could not find log of LLVM functions in specified directory\n");
        exit(1);
    }

    // Initialize test function pass
    FunctionPassManager *FPasses = new FunctionPassManager(Mod);
    FunctionPass *fp = static_cast<FunctionPass*>(createTestFunctionPass());
    FPasses->add(fp);
    FPasses->doInitialization();

    char funcline[500];
    Function *F;

    // Check trace
    while (true){
        strncpy(funcline, "\0", 1);
        char *s = fgets(funcline, sizeof(funcline), flog);

        if (feof(flog)){
            break; // Done processing trace
        }

        // System call information - ignore for test
        if (!strncmp(funcline, "taint", 5)){
            continue;
        }

        funcline[strlen(funcline)-1] = '\0'; // remove newline
        F = Mod->getFunction(funcline);
        if (F == NULL){
            fprintf(stderr, "Error: unknown function, %s\n", funcline);
            exit(1);
        }

        //printf("%s\n", F->getName().str().c_str());
        FPasses->run(*F); // Call runOnFunction()
    }
    fclose(flog);
    fclose(dlog);
    printf("Trace and dynamic log are aligned.\n");
    return 0;
}


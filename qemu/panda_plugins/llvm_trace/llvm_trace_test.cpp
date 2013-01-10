
/*
 * This test recreates an entire trace in LLVM format, and ensures that dynamic
 * values line up with their expected location in the bitcode.
 *
 * TODO: This doesn't support helper functions, but we will add support for them
 * here too.
 */

#include "stdio.h"

#include "llvm/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Value.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Support/IRReader.h"
#include "llvm/Support/raw_ostream.h"

extern "C" {
#include "panda_memlog.h"
}

using namespace llvm;

FILE *flog;          // Function log
FILE *dlog;          // Dynamic value log
BasicBlock *next_bb; // Taken branch for BB that needs to be processed next
bool ret;            // Return flag

/* TestInstVisitor class
 * This class visits instructions for the TestFunctionPass.
 */
class TestInstVisitor : public InstVisitor<TestInstVisitor> {

public:
    TestInstVisitor(){}
    ~TestInstVisitor(){}

    void visitLoadInst(LoadInst &I);
    void visitStoreInst(StoreInst &I);
    void visitBranchInst(BranchInst &I);
    void visitReturnInst(ReturnInst &I);
    //void visitSelectInst(SelectInst &I);
    //void visitCallInst(CallInst &I);
};

void TestInstVisitor::visitLoadInst(LoadInst &I){
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    assert((entry.entrytype == ADDRENTRY)
        && (entry.entry.memaccess.op == LOAD));
}

void TestInstVisitor::visitStoreInst(StoreInst &I){
    if (I.isVolatile()){
        return; // These are part of the runtime system that we don't log
    }

    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    assert((entry.entrytype == ADDRENTRY)
        && (entry.entry.memaccess.op == STORE));
}

void TestInstVisitor::visitBranchInst(BranchInst &I){
    DynValEntry entry;
    size_t n = fread(&entry, sizeof(DynValEntry), 1, dlog);
    assert(entry.entrytype == BRANCHENTRY);
    next_bb = I.getSuccessor(entry.entry.branch.br);
}

void TestInstVisitor::visitReturnInst(ReturnInst &I){
    ret = true;
}

/* TestFunctionPass
 * This class is a test function pass responsible for analyzing an LLVM trace to
 * make sure the dynamic log lines up.
 */
class TestFunctionPass : public FunctionPass {

public:
    static char ID;
    TestInstVisitor *TIV;

    TestFunctionPass() : FunctionPass(ID), TIV(new TestInstVisitor()) {}
    ~TestFunctionPass();

    bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }
};

TestFunctionPass::~TestFunctionPass(){
    delete TIV;
}

bool TestFunctionPass::runOnFunction(Function &F){
    ret = false;

    // Process function starting with the entry basic block
    Function::iterator bb = F.begin();
    TIV->visit(bb);

    // If a function has multiple basic blocks, process them until we reach ret
    if (F.size() > 1){
        while (!ret){ // Continue until we reach a return instruction
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
    //cl::opt<std::string> CacheFile("c",
    //    cl::desc("helper taint cache (optional)"), cl::Optional);
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
        Err.Print(argv[0], errs());
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
    
    FunctionPassManager *FPasses = new FunctionPassManager(Mod);
    
    // Are we reading from the taint cache?
    /*FILE *tc = NULL;
    if (!CacheFile.empty()){
        tc = fopen(CacheFile.c_str(), "r");
        if (tc == NULL){
            printf("Error opening taint cache file\n");
            exit(1);
        }
    }*/

    // Initialize test function pass
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

        FPasses->run(*F); // Call runOnFunction()
    }
    fclose(flog);
    fclose(dlog);
    printf("Trace and dynamic log are aligned.\n");
    return 0;
}


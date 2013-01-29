
/*
 * Not really a plugin per se, but rather a tool for analyzing call graphs of
 * QEMU helper functions.  Also, we may want some architecture-specific
 * compile-time details, so that's why we build arch-specific versions in the
 * plugin framework.
 */

#include "stdio.h"

#include <set>

#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/IRReader.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

class PandaCallGraphPass : public ModulePass {
public:
    static char ID;
    PandaCallGraphPass() : ModulePass(ID) {
        PassRegistry &Reg = *PassRegistry::getPassRegistry();
        initializeIPA(Reg); // Initialize call graph analysis
    }
    ~PandaCallGraphPass(){}
    virtual bool runOnModule(Module &M);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const{
        AU.setPreservesAll();
        AU.addRequired<CallGraph>();
    }
};

char PandaCallGraphPass::ID = 0;
static RegisterPass<PandaCallGraphPass> X("PCGP", "Panda Call Graph Pass");

bool PandaCallGraphPass::runOnModule(Module &M){
    CallGraph &CG = getAnalysis<CallGraph>();
    
    // Tell us which intrinsics are called
    printf("=== Intrinsics called: ===\n");
    for (Module::iterator i = M.begin(); i != M.end(); i++){
        if (i->isDeclaration() && i->isIntrinsic()){
            printf("%s\n", i->getName().str().c_str());
        }
    }
    printf("\n\n");

    std::set<Function*> funcset;

    for (Module::iterator i = M.begin(); i != M.end(); i++){

        if (i->isDeclaration()){
            // If it's defined somewhere else that's not op_helper.c 
            continue;
        }

        printf("=== %s ===\n", i->getName().str().c_str());
        funcset.clear();
        for (CallGraphNode::iterator j = CG[i]->begin(); j != CG[i]->end();
                j++){
            Function *f = j->second->getFunction();
            if (f){
                if (funcset.find(f) == funcset.end()){
                    // Only print a called function once
                    printf("%s\n", f->getName().str().c_str());
                    funcset.insert(f);
                }
            }
            else {
                // Call to an LLVM value or inline ASM (yes, you can inline ASM
                // in the IR)
                printf("NULL FUNCTION\n");
            }
        }
        printf("\n\n");

    }

    return false; // doesn't modify
}

namespace {
    cl::opt<std::string> module("m", cl::desc("LLVM bitcode module"),
        cl::Required);
}

int main(int argc, char **argv){
    // Load the bitcode
    cl::ParseCommandLineOptions(argc, argv, "bitcode_callgraph\n");
    SMDiagnostic Err;     
    LLVMContext &Context = getGlobalContext();
    Module *Mod = ParseIRFile(module, Err, Context);
    if (!Mod) {
        Err.Print(argv[0], errs());
        exit(1);
    }
    
    // Run the analysis
    PassManager *PM = new PassManager();
    Pass *P = static_cast<Pass*>(new PandaCallGraphPass());
    PM->add(P);
    PM->run(*Mod);
    delete PM;

    return 0;
}


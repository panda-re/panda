/* PANDABEGINCOMMENT PANDAENDCOMMENT */

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

//#define PRINTCG

using namespace llvm;

class PandaCallGraphPass : public ModulePass {
    int curdepth;
    int maxdepth;
    Function *currentFunc;
    Function *deepestFunc;
    std::set<Function*> externalFuncs;
    std::set<Function*> recursiveFuncs;
    std::set<Function*> nullFuncs;
    std::set<std::string> instrs;

    void visitNode(CallGraphNode *node);
    void getInstructions(Function *F);
    void printReport(Module &M);
public:
    static char ID;
    PandaCallGraphPass() : ModulePass(ID), curdepth(0), maxdepth(0) {
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

void PandaCallGraphPass::visitNode(CallGraphNode *node){
    curdepth++;
    if (curdepth > maxdepth){
        maxdepth++;
        deepestFunc = currentFunc;
    }

    std::set<Function*> funcset; // Edges for this node
    for (CallGraphNode::iterator i = node->begin(); i != node->end(); i++){
        Function *f = i->second->getFunction();
        if (f){
            if (funcset.find(f) != funcset.end()){
                // Only visit a called function once
                continue;
            }
            funcset.insert(f);
#ifdef PRINTCG
            for (int j = 0; j < curdepth; j++) printf(" ");
            printf("%s ", f->getName().str().c_str());
#endif
            if (i->second->getFunction()->isDeclaration()){
                externalFuncs.insert(f);
#ifdef PRINTCG
                printf("-- EXTERNAL\n");
#endif
            }
            else {
                if (f == node->getFunction()){
                    recursiveFuncs.insert(f);
#ifdef PRINTCG
                    printf("-- RECURSIVE\n");
#endif
                }
                else {
#ifdef PRINTCG
                    printf("\n");
#endif
                    visitNode(i->second);
                }
            }
        }
        else {
            // Call to an LLVM value or inline ASM (yes, you can inline ASM
            // in the IR)
            nullFuncs.insert(node->getFunction());
#ifdef PRINTCG
            for (int j = 0; j < curdepth; j++) printf(" ");
            printf("NULL FUNCTION\n");
#endif
        }
    }
    curdepth--;
}

void PandaCallGraphPass::getInstructions(Function *F){
    for (Function::iterator i = F->begin(); i != F->end(); i++){
        for (BasicBlock::iterator j = i->begin(); j != i->end(); j++){
            instrs.insert(j->getOpcodeName());
        }
    }
}

void PandaCallGraphPass::printReport(Module &M){
    printf("=== Intrinsics called: ===\n");
    for (Module::iterator i = M.begin(); i != M.end(); i++){
        if (i->isDeclaration() && i->isIntrinsic()){
            printf("%s\n", i->getName().str().c_str());
        }
    }
    printf("\n\n");
    
    printf("=== External functions: ===\n");
    for (std::set<Function*>::iterator i = externalFuncs.begin();
            i != externalFuncs.end(); i++){
        printf("%s\n", (*i)->getName().str().c_str());
    }
    printf("\n\n");

    printf("=== Recursive functions: ===\n");
    for (std::set<Function*>::iterator i = recursiveFuncs.begin();
            i != recursiveFuncs.end(); i++){
        printf("%s\n", (*i)->getName().str().c_str());
    }
    printf("\n\n");
    
    printf("=== Functions with null calls: ===\n");
    for (std::set<Function*>::iterator i = nullFuncs.begin();
            i != nullFuncs.end(); i++){
        printf("%s\n", (*i)->getName().str().c_str());
    }
    printf("\n\n");
    
    printf("=== Maximum call depth: ===\n%d, %s\n\n\n", maxdepth,
        deepestFunc->getName().str().c_str());

    printf("=== LLVM instructions: ===\n");
    for (std::set<std::string>::iterator i = instrs.begin();
            i != instrs.end(); i++){
        printf("%s\n", (*i).c_str());
    }
    printf("\n\n");
}

bool PandaCallGraphPass::runOnModule(Module &M){
    CallGraph &CG = getAnalysis<CallGraph>();
    
    // Look at call graph for each function in module
    for (Module::iterator i = M.begin(); i != M.end(); i++){
        if (i->isDeclaration()){
            // If it's defined somewhere else that's not op_helper.c 
            continue;
        }

#ifdef PRINTCG
        printf("=== %s ===\n", i->getName().str().c_str());
#endif
        currentFunc = i;
        visitNode(CG[i]);

        getInstructions(i);

#ifdef PRINTCG
        printf("\n\n");
#endif
    }

    printReport(M);

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


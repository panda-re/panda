
/*
 * This function pass can be used in a plugin for generated code to change LLVM
 * function calls and function names to the associated LLVM versions that we've
 * generated bitcode for.
 */

#include "stdio.h"

#include "llvm/Transforms/Utils/Cloning.h"

#include "panda_helper_call_morph.h"

using namespace llvm;



/***
 *** PandaCallMorphFunctionPass
 ***/



char PandaCallMorphFunctionPass::ID = 0;
static RegisterPass<PandaCallMorphFunctionPass>
Y("PandaCallMorph", "Change helper function calls to the the LLVM version");

bool PandaCallMorphFunctionPass::runOnFunction(Function &F){
    functionChanged = false;
    PHCV->visit(F);
    return functionChanged;
}



/***
 *** PandaHelperCallVisitor
 ***/



void PandaHelperCallVisitor::visitCallInst(CallInst &I){
    assert(I.getCalledFunction());
    if (I.getCalledFunction()->isIntrinsic()){
        return; // Ignore intrinsics
    }
    Module *m = I.getParent()->getParent()->getParent();
    assert(m);
    std::string origName = I.getCalledFunction()->getNameStr();
    std::string newName = origName.append("_llvm");
    Function *newFunction = m->getFunction(newName);
    assert(newFunction);
    I.setCalledFunction(newFunction);
    PCMFP->functionChanged = true;
}


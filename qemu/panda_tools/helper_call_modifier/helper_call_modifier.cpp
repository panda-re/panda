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
 * This is a tool that is used during the QEMU build process.  The idea is that
 * PANDA plugins might want to run LLVM instrumentation or analysis passes over
 * QEMU helper functions.  So we build an LLVM bitcode module consisting of most
 * functions used in helper function processing.  We need to change all names
 * and references of regular helper functions to LLVM versions of helper
 * functions.  To do this, a plugin will need to load the output of this file (a
 * byproduct of the QEMU build process), perform analysis, and link into the
 * JIT.  It will also need to run the call modification pass on generated code
 * to call these LLVM versions of helper functions.
 */

#include "stdio.h"

#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/IRReader.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;

namespace {
    cl::opt<std::string> InputFile("i", cl::desc("input bitcode"),
        cl::Required);
    cl::opt<std::string> OutputFile("o", cl::desc("output bitcode"),
        cl::Required);
}

int main(int argc, char **argv){
    // Load the bitcode
    cl::ParseCommandLineOptions(argc, argv, "helper_call_modifier\n");
    SMDiagnostic Err;     
    LLVMContext &Context = getGlobalContext();
    Module *Mod = ParseIRFile(InputFile, Err, Context);
    if (!Mod) {
        Err.Print(argv[0], errs());
        exit(1);
    }
    
    /*
     * This iterates through the list of functions, copies/renames, and deletes
     * the original function.  This is how we have to do it with the while loop
     * because of how the LLVM function list is implemented.
     */
    Module::iterator i = Mod->begin();
    while (i != Mod->end()){
        Function *f = i;
        i++;
        
        Module *m = f->getParent();
        assert(m);
        if (!f->isDeclaration()){ // internal functions only
            Function *newFunc = CloneFunction(f);
            std::string origName = f->getNameStr();
            std::string newName = origName.append("_llvm");
            newFunc->setName(newName);
            /*
             * XXX: We need to remove stack smash protection from helper
             * functions that are to be compiled with the JIT.  There is a bug
             * in LLVM 3.0 that causes the JIT to generate stack protection code
             * that causes the program to segfault.  More information available
             * here: http://llvm.org/bugs/show_bug.cgi?id=11089
             */
            newFunc->removeFnAttr(Attribute::StackProtectReq);
            // push to the front so the iterator doesn't see them again
            m->getFunctionList().push_front(newFunc);
            f->replaceAllUsesWith(newFunc);
            f->eraseFromParent();
        }
    }
    
    // Verify the new bitcode and write it out, printing errors if necessary
    std::string errstring;
    verifyModule(*Mod, PrintMessageAction, &errstring);
    raw_fd_ostream *fstream = new raw_fd_ostream(OutputFile.c_str(), errstring);
    WriteBitcodeToFile(Mod, *fstream);
    printf("%s", errstring.c_str());
    fstream->close();

    return 0;
}


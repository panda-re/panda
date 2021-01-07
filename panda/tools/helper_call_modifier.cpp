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

#include <cstdio>
#include <iostream>
#include <regex>

#include "llvm/Support/SourceMgr.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm-c/Core.h"
#include "llvm-c/Target.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

using namespace llvm;

namespace {
    cl::opt<std::string> InputFile("i", cl::desc("input bitcode"),
        cl::Required);
    cl::opt<std::string> OutputFile("o", cl::desc("output bitcode"),
        cl::Required);
}

int main(int argc, char **argv) {

    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();

    // Load the bitcode
    cl::ParseCommandLineOptions(argc, argv, "helper_call_modifier\n");
    SMDiagnostic Err;
    LLVMContext Context;
    std::unique_ptr<Module> Mod = parseIRFile(InputFile, Err, Context);
    if (Mod == nullptr) {
        Err.print(argv[0], errs());
        exit(1);
    }

    /*
     * This iterates through the list of functions, copies/renames, and deletes
     * the original function.  This is how we have to do it with the while loop
     * because of how the LLVM function list is implemented.
     */
    std::regex mmu_regex("helper_[bl]e_(ld|st)[us]?[bwlq]_mmu(_panda)?",
            std::regex::egrep);

    std::vector<Function*> funcs;
    for (Function &f : *Mod) {
        funcs.push_back(&f);
    }

    for (Function *f : funcs) {
        std::string fname = f->getName().str();
        std::string newName = fname;
        if (std::regex_match(fname, mmu_regex)) {
            newName.append("_panda");
            f->setName(newName);
        } else if (!f->isDeclaration() && fname.find("helper_") == 0) {
            newName.append("_llvm");
            ValueToValueMapTy VMap;
            Function *newFunc = CloneFunction(f, VMap, nullptr);
            newFunc->setName(newName);
            /*
             * XXX: We need to remove stack smash protection from helper
             * functions that are to be compiled with the JIT.  There is a bug
             * in LLVM 3.0 that causes the JIT to generate stack protection code
             * that causes the program to segfault.  More information available
             * here: http://llvm.org/bugs/show_bug.cgi?id=11089
             */
            const AttributeList AS = newFunc->getAttributes();
            newFunc->setAttributes(AS.removeAttribute(newFunc->getContext(),
                AttributeList::FunctionIndex, Attribute::StackProtectReq));
            f->replaceAllUsesWith(newFunc);
            f->eraseFromParent();
        }
    }

    // Verify the new bitcode and write it out, printing errors if necessary
    bool brokenDebug = false;
    if(verifyModule(*Mod, &llvm::errs(), &brokenDebug)) {
        std::cerr << "Module could not be verified";
    } else {
        std::error_code err;
        raw_fd_ostream fstream(OutputFile.c_str(), err);
        if(err) {
            std::cerr << err.message();
        } else {
            WriteBitcodeToFile(*Mod, fstream);
        }
    }

    return 0;
}


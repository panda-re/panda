#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>

#include <bitset>
#include <vector>
#include <set>
#include <stack>
#include <map>

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


using namespace llvm;

#define MAX_BITSET 2048

// Don't ever call this with an array of size < MAX_BITSET/8
void bits2bytes(std::bitset<MAX_BITSET> &bs, uint8_t out[]) {
    for (int i = 0; i < MAX_BITSET / 8; i++) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; j++) {
            byte |= (bs[(i*8) + j] << j);
        }
        out[i] = byte;
    }
}

void print_insn(Instruction *insn) {
    std::string s;
    raw_string_ostream ss(s);
    insn->print(ss);
    ss.flush();
    printf("%s\n", ss.str().c_str());
    return;
}

void print_marked(Function *f, std::map<Function *, std::vector<std::bitset<MAX_BITSET>>> &marked) {
    printf("*** Function %s ***\n", f->getName().str().c_str());
    int i = 0;
    for (Function::iterator it = f->begin(), ed = f->end(); it != ed; ++it) {
        printf(">>> Block %d\n", i);
        int j = 0;
        for (BasicBlock::iterator insn_it = it->begin(), insn_ed = it->end();
                insn_it != insn_ed; ++insn_it) {
            char m = marked[f][i][j] ? '*' : ' ';
            printf("%c ", m);
            print_insn(&*insn_it);
            j++;
        }
        i++;
    }
}

void bytes2bits(uint8_t bytes[], std::bitset<MAX_BITSET> &bits) {
    for (int i = 0; i < MAX_BITSET / 8; i++) {
        uint8_t byte = bytes[i];
        for (int j = 0; j < 8; j++) {
            bits[(i*8) + j] = (byte >> j) & 1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <llvm-mod.bc> <slice_report.bin> <function> [<function> ...]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    LLVMContext &ctx = getGlobalContext();

    // Load the bitcode...
    SMDiagnostic err;

    Module *mod = ParseIRFile(argv[1], err, ctx);

    std::map<Function *, std::vector<std::bitset<MAX_BITSET>>> marked;
    FILE *f = fopen(argv[2], "rb");
    while (!feof(f)) {
        uint32_t name_size = 0;
        uint32_t index = 0;
        uint8_t bytes[MAX_BITSET/8] = {};
        
        // Name size
        if (1 != fread(&name_size, sizeof(uint32_t), 1, f))
            break;
        
        // Name
        char *cname = (char *) malloc(name_size);
        fread(cname, name_size, 1, f);
        std::string name(cname, name_size);
        free(cname);

        fread(&index, sizeof(uint32_t), 1, f);
        fread(bytes, MAX_BITSET / 8, 1, f);

        Function *fn = mod->getFunction(name);
        assert(fn != NULL);

        std::bitset<MAX_BITSET> bits;
        bytes2bits(bytes, bits);

        if (index >= marked[fn].size())
            marked[fn].resize(index+1);
        marked[fn][index] = bits;
    }

    for (int i = 3; i < argc; i++) {
        Function *fn = mod->getFunction(argv[i]);
        if (fn == NULL) {
            printf("Function %s does not exist. Skipping.\n", argv[i]);
            continue;
        }
        if (marked.find(fn) == marked.end()) {
            printf("Function %s has no marked instructions.\n", argv[i]);
            continue;
        }
        print_marked(fn, marked);
    }

    return EXIT_SUCCESS;
}

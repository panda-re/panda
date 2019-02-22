#include <stdio.h>
#include <iostream>
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

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/Support/TargetRegistry.h"

using namespace llvm;

#define MAX_BITSET 2048
FILE *sliceAddrFile = fopen("slice_addrs", "wb");

// map<char* module_name, uint64_t> markedMap_addrs;

std::map<std::string, uint32_t> instr_hits;

int basic_block_count = 0;


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

void bytes2bits(uint8_t bytes[], std::bitset<MAX_BITSET> &bits) {
    for (int i = 0; i < MAX_BITSET / 8; i++) {
        uint8_t byte = bytes[i];
        for (int j = 0; j < 8; j++) {
            bits[(i*8) + j] = (byte >> j) & 1;
        }
    }
}

void hex2bytes(std::string hex, unsigned char outBytes[]){
     const char* pos = hex.c_str();
     for (int ct = 0; ct < hex.length()/2; ct++){
        sscanf(pos, "%2hhx", &outBytes[ct]);
        pos += 2;           
    }
}

void print_target_asm(LLVMDisasmContextRef dcr, std::string targetAsm, bool is_marked, uint64_t baseAddr, uint32_t hit_count){
    char c = is_marked ? '*' : ' ';
    unsigned char* u = new unsigned char[targetAsm.length()/2];
    hex2bytes(targetAsm, u); 
    char *outinst = new char[50];

    // disassemble target asm
    LLVMDisasmInstruction(dcr, u, targetAsm.length()/2, baseAddr, outinst, 50);   
    printf("%c %s\n", c, outinst);

    // count_inst(outinst);

    // Write to slice_addrs file
    // Also count number of hits to this addr, based on 
    if (is_marked) {
        fprintf(sliceAddrFile, "%lx:%d\n", baseAddr, hit_count);
        // markedMap_addrs[lib_name]
    }
}

/*
* Various metrics to compare string computations — counting types of arith instructions
* xor, add, sub, mul, 
*/
void compute_statistics() {


}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <llvm-mod.bc> <slice_report.bin>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    //// Load the bitcode...`
    LLVMContext &ctx = getGlobalContext();
    SMDiagnostic err;
    Module *mod = ParseIRFile(argv[1], err, ctx);

    // Load the disassembler
    LLVMInitializeAllAsmPrinters();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllDisassemblers();

    LLVMDisasmContextRef dcr = LLVMCreateDisasm (
        "i386-unknown-linux-gnu",
        NULL,
        0,
        NULL,
        NULL
    );

    LLVMSetDisasmOptions(dcr, LLVMDisassembler_Option_AsmPrinterVariant | LLVMDisassembler_Option_UseMarkup); 

    // map of Functions to hitcount, bitset 
    std::map<Function *, std::pair<uint32_t, std::vector<std::bitset<MAX_BITSET>>>> markedMap;
    FILE *f = fopen(argv[2], "rb");

    while (!feof(f)) {
        uint32_t name_size = 0;
        uint32_t bb_idx = 0;
        uint32_t hit_count = 0;
        uint8_t bytes[MAX_BITSET/8] = {};
        
        //// Name size
        if (1 != fread(&name_size, sizeof(uint32_t), 1, f))
            break;
        
        //// Name
        
        char *cname = new char[name_size];
        fread(cname, name_size, 1, f);
        std::string name(cname, name_size);
        // printf("name %s\n", name.c_str());

        fread(&bb_idx, sizeof(uint32_t), 1, f);
        fread(&hit_count, sizeof(uint32_t), 1, f);
        fread(bytes, MAX_BITSET / 8, 1, f);

        Function *fn = mod->getFunction(name);
        assert(fn != NULL);

        std::bitset<MAX_BITSET>* bits = new std::bitset<MAX_BITSET>();
        bytes2bits(bytes, *bits);

        if (bb_idx >= markedMap[fn].second.size()) {
            markedMap[fn].second.resize(bb_idx+1);
		}

        markedMap[fn].first = hit_count;
        markedMap[fn].second[bb_idx] = *bits;
    }

    // Now, print markedMap assembly
    for (auto keyval : markedMap) {
        Function* f = keyval.first;
        uint32_t hit_count = keyval.second.first;
        printf("*** Function %s , hitcount %d***\n", f->getName().str().c_str(), hit_count);
		
		int tb_num;
		uint64_t base_addr;
        int num_filled = sscanf(f->getName().str().c_str(), "tcg-llvm-tb-%d-%lx", &tb_num, &base_addr);
		if (num_filled != 2) {
            printf("Is not a guest tb\n");
            continue;
        }; 

        int i = 0;
        for (Function::iterator it = f->begin(), ed = f->end(); it != ed; ++it) {
            printf(">>> Block %d\n", i);

			if (i >= markedMap[f].second.size()) {
				break;
			}

            int j = 0;
            std::string targetAsm = "";
            bool targetAsmSeen, targetAsmMarked = false;

            for (BasicBlock::iterator insn_it = it->begin(), insn_ed = it->end();
                    insn_it != insn_ed; ++insn_it) {
                    
                if (MDNode* N = insn_it->getMetadata("targetAsm")){

                    if (!targetAsm.empty()){
						printf("%lx ", base_addr);
                        print_target_asm(dcr, targetAsm, targetAsmMarked, base_addr, hit_count);
                        base_addr += targetAsm.length()/2;
                    }                    
                    
                    // updated targetAsm
                    targetAsm = cast<MDString>(N->getOperand(0))->getString();
                    targetAsmSeen = false;
                    targetAsmMarked = false;
                }

                // If this llvm instruction is markedMap and we haven't already printed target asm for this inst
                if (markedMap[f].second[i][j] && !targetAsmSeen){
                    //Print target asm
                    targetAsmSeen = true;
                    targetAsmMarked = true;
                };

                j++;
            }
            
            //Print last instruction and mark
            if (!targetAsm.empty()){
				printf("%lx ", base_addr);
                print_target_asm(dcr, targetAsm, targetAsmMarked, base_addr, hit_count);
            }                    
            i++;
        }
    }   

    return EXIT_SUCCESS;
}

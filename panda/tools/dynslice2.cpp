
/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Ray Wang        raywang@mit.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */


/*
 * This plugin contains the core logic to do dynamic slicing on an LLVM bitcode module + tracefile
 * It generates a tracefile that can be used by the same tool to mark llvm bitcode 
 * I can use metadata to mark the llvm bitcode in a pass
 *
 * The C struct is defined in llvm_trace2.proto
 *
 */

#include <vector>
#include <map>
#include <set>
#include <stack>
#include <bitset>

#include "dynslice2.h"

#include "panda/plog-cc.hpp"
#include "panda/plog_reader.hpp"

extern "C" {
#include "panda/addr.h"
}

#include <iostream>
#include <fstream>
#include <sstream>

#include <llvm/PassManager.h>
#include <llvm/PassRegistry.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IRReader/IRReader.h"
#include <llvm/InstVisitor.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Pass.h>
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Regex.h"

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

// boost graphing
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/graph_utility.hpp>
// #include <boost/throw_exception.hpp>

#define BOOST_NO_EXCEPTIONS
#include <boost/throw_exception.hpp>
void boost::throw_exception(std::exception const & e){
//do nothing
}

#define MAX_BITSET 2048

/* plog-cc.cpp dependencies.

   These are needed so we can link with the same version of plog-cc.o that is
   linked with the main PANDA binary.

   As long as this file only calls functions that read a pandalog file, these
   will never be accessed by dynslice2. */

int panda_in_main_loop = 0;
struct CPUTailQ cpus;

target_ulong panda_current_pc(CPUState *env) {
    assert(false);
}

using namespace llvm;
using namespace boost;

/*
 * Switch statement to handle all instructions
 * and update the uses and defines lists 
 *
 * Instead of reversing the log, I search through to the end for the last occurrence of the 
 * instruction criterion I want using an LLVM pass (like Giri).
 *
 * Then, with this criterion, I can work backwards and find the uses/definitions. 
 * 
 * I need a working set, uses, and definitions set. 
 */

typedef std::pair<SliceVarType, uint64_t> SliceVar;
 
// maintain a worklist for each SliceVar, so we can keep track of SCN for each one. 
// pair of SCN, set of <SliceVar, depth>
typedef std::map<SliceVar, std::pair<int, std::map<SliceVar, int>>> slice_work_lists_t;
slice_work_lists_t slice_work_lists;

// map SliceVars to Instruction enum: count
std::map<SliceVar, std::map<int, int>> slice_count;  

int ret_ctr = 0;
LLVMDisasmContextRef dcr;

uint64_t cpustatebase;
llvm::Module* mod;
std::map<uint64_t, int> tb_addr_map;

std::map<std::string, uint64_t> base_addr_map;

// Slicing globals 
uint64_t startRRInstrCount;
uint64_t endRRInstrCount;
uint64_t start_addr;
uint64_t end_addr;
std::set<uint64_t> searchTbs;
std::set<std::string> searchModules;

// std::string cur_vma;
bool markedInsideBB = false; 

// std::set<SliceVar> work_list; 
std::vector<traceEntry> trace_entries;

// markedMap maps Function, bb_idx pairs to count for function, bitset of each instruction
std::map<std::pair<Function*, int>, std::pair<int, std::bitset<MAX_BITSET>>> markedMap;

bool debug = false;
uint64_t last_pc = 0;

// tainted_ptr option should cause the LLVM value determining the load or store address to be tracked in slice, as well as the guest RAM addr
// this affects slice
bool tainted_ptr = false;

std::vector<std::string> registers = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP", "EFLAGS", "CC_DST", "CC_SRC", "CC_SRC2", "CC_OP", "DF"};
 
std::unique_ptr<panda::LogEntry> cursor;

// graphing stuff
struct Vertex{ 
    std::string slice_var; 
    int slice_var_type; 
    unsigned opcode;
    uint64_t value;
    bool scn;
};

typedef boost::adjacency_list<boost::listS, boost::vecS, boost::bidirectionalS, Vertex> Graph;
typedef boost::graph_traits<Graph>::vertex_descriptor vertex_t;
typedef boost::graph_traits<Graph>::edge_descriptor edge_t;

const char* get_opcode_name(unsigned opcode) {
    if (opcode == 255) {
        return "mem_load";
    } else if (opcode == 256) {
        return "mem_store";
    } else {
        return Instruction::getOpcodeName(opcode);
    }
}

// property writer for Vertex
template <class Name>
class myVertexWriter {
public:
     myVertexWriter(Name _name) : name(_name) {}
     template <class VertexOrEdge>
     void operator()(std::ostream& out, const VertexOrEdge& v) const {

            std::string opcode = name[v].opcode ? get_opcode_name(name[v].opcode) : "";

            // only print value if load or store
            switch (name[v].opcode) {
            case Instruction::Load:
            case Instruction::Store:
            case 255:
            case 256:
                out << std::hex << "[label=\"" << "(" << opcode << ") " << name[v].slice_var << "\n" << "val: " << name[v].value << "\"";
                break;
            default:
                out << std::hex << "[label=\"" << "(" << opcode << ") " << name[v].slice_var << "\"";
            }


            if (name[v].scn) {
                out << " color=red style=filled";
            }

            switch (name[v].slice_var_type) {
            case -1:
                out << " color=green style=filled";
                break;
            case MEM:
                out << " color=gray style=filled";
                break;
            case TGT: 
                out << " color=yellow style=filled";                
                break;
            }

            out << "]";
     }
private:
     Name name;
};

// map SliceVars to vertex_descriptors
std::map<SliceVar, vertex_t> vertex_table;
std::map<SliceVar, vertex_t> scn_vertex_table;

// Define Graph
Graph g;
Graph scn_g;

//******************************************************************
// Helper functions 
//*****************************************************************
void hex2bytes(std::string hex, unsigned char outBytes[]){
     const char* pos = hex.c_str();
     for (int ct = 0; ct < hex.length()/2; ct++){
        sscanf(pos, "%2hhx", &outBytes[ct]);
        pos += 2;           
    }
}

void print_target_asm(LLVMDisasmContextRef dcr, std::string target_asm, bool marked, uint64_t baseAddr){
    char c = marked ? '*' : ' ';
    unsigned char* u = new unsigned char[target_asm.length()/2];
    hex2bytes(target_asm, u); 
    char *outstring = new char[50];

    // disassemble target asm
    LLVMDisasmInstruction(dcr, u, target_asm.length()/2, baseAddr, outstring, 50);   
    printf("%c %s\n", c, outstring);
}


unsigned get_opcode(traceEntry &t) {
    if (t.inst->getOpcode() == Instruction::Call) {

        CallInst* c = dyn_cast<CallInst>(t.inst);

        Function *subf = c->getCalledFunction();
        StringRef func_name = subf->getName();

         if (Regex("helper_([lb]e|ret)_ld.*_mmu_panda").match(func_name)) {
            return 255;
        } else if (Regex("helper_([lb]e|ret)_st.*_mmu_panda").match(func_name) || func_name.startswith("llvm.memset")) {
            return 256;
        } else {
            return Instruction::Call;
        }
    } else {
        return t.inst->getOpcode();
    }
}



//******************************************************************
// Print functions 
//*****************************************************************

std::string slicevar_to_str(const SliceVar &s) {
    char output[128] = {};

    switch (s.first) {
        case LLVM:
            sprintf(output, "LLVM_%lx", s.second);
            break;
        case MEM:
            sprintf(output, "MEM_%lx", s.second);
            break;
        case HOST:
            sprintf(output, "HOST_%lx", s.second);
            break;
        case TGT: {
            uint64_t offset = (s.second - cpustatebase)/4;
            if (offset < registers.size()) {
                std::string reg = registers[offset];
                sprintf(output, "TGT_%s", reg.c_str());    
            } else {
                sprintf(output, "TGT_%lx", s.second);
            }
            
            break;
        }
        case SPEC:
            sprintf(output, "SPEC_%lx", s.second);
            break;
        case FRET:
            sprintf(output, "RET_%lx", s.second);
            break;
        default:
            assert (false && "No such SliceVarType");
    }

    return output;
}

void print_slice_count(std::map<int, int> inst_count) {
    std::cout << "{";
    std::string opcode;
    for (auto it: inst_count) {
        opcode = Instruction::getOpcodeName(it.first);
        std::cout << opcode << ": " << it.second << ", ";
    }
    std::cout << "}" << std::endl;
}

void print_insn(Instruction *insn) {
    std::string s;
    raw_string_ostream ss(s);
    insn->print(ss);
    ss.flush();
    printf("%s\n", ss.str().c_str());
    return;
}

void print_set(std::set<SliceVar> &s) {
    printf("{");
    for (const SliceVar &w : s) printf(" %s", slicevar_to_str(w).c_str());
    printf(" }\n");
}

void print_set(std::map<SliceVar, int> &s) {
    printf("{");
    for (auto &w : s) printf(" %s", slicevar_to_str(w.first).c_str());
    printf(" }\n");
}

void print_slice_worklist(slice_work_lists_t &s) {
    printf("{");
    for (auto w : s) {
        printf("Var: %s, scn: %d\t", slicevar_to_str(w.first).c_str(), w.second.first);
        print_set(w.second.second);
    } 
    printf(" }\n");
}

uint64_t infer_offset(const char* reg){

    ptrdiff_t pos = std::distance(registers.begin(), std::find(registers.begin(), registers.end(), reg));
    if (pos < registers.size()) {
        return pos;
    } else {
        printf("NOT an x86 reg: %s\n", reg);
        return -1;
    }
}


void insert_criteria(std::string str){
    
    SliceVarType typ = LLVM;
    std::string crit = str.substr(0, str.find(" at ")); 

	if (strncmp(str.c_str(), "MEM", 3) == 0) {
        // slicing on a memory address
        typ = MEM;
        std::string mem_range = crit.substr(4, crit.length());
        std::string start_mem_str = mem_range.substr(0, mem_range.find("-"));
        mem_range.erase(0, mem_range.find("-") + 1);
        std::string end_mem_str = mem_range;
        std::cout << "start mem str " << start_mem_str << " end_mem_str " << end_mem_str << std::endl;

        uint64_t start_mem_addr = std::stoull(start_mem_str, nullptr, 16);
        uint64_t end_mem_addr = std::stoull(end_mem_str, nullptr, 16);

        for (uint64_t addr = start_mem_addr; addr < end_mem_addr; addr++) {
            printf("Adding mem addr %lx\n", addr);
            slice_work_lists[std::make_pair(typ, addr)] = {0, {{std::make_pair(typ, addr), 0}}};
        }
    }
    else if (strncmp(str.c_str(), "TGT", 3) == 0) {
        // we are slicing on a target register
        typ = TGT;
        std::string reg = crit.substr(4, crit.length());
        uint64_t sliceVal = cpustatebase + infer_offset(reg.c_str())*4;
        slice_work_lists[std::make_pair(typ, sliceVal)] = {0, {{std::make_pair(typ, sliceVal), 0}}};
    }

    //searchTbs.insert(addr_to_tb(start_addr));
}

/**
 * Processes criteria from criteria file
 * Gets list of modules to slice on
 */
void process_criteria(std::string criteria_fname){
    std::cout << "Processing criteria" << std::endl;
    
    std::string str;
    std::ifstream file(criteria_fname);

    if(!file.is_open()){
        std::cout << "process_criteria: error opening criteria file" << std::endl;
        exit(1);
    }

    // get all initial worklist criteria
    while (std::getline(file, str))
    {
        // process virtual modules list
        if (strncmp(str.c_str(), "VMA:", 4) == 0) {
            std::string modules = str.substr(4, str.length()); 
            std::istringstream modulestream(modules);
            std::cout << modules << std::endl;

            int pos;
            std::string module_name;
            while (getline(modulestream, module_name, ',')) {
                printf("adding module %s\n", module_name.c_str());
                searchModules.insert(module_name);
            }
        }
        // Process str, if it is a MEM or REG criteria
		else if (strncmp(str.c_str(), "MEM", 3) == 0 || strncmp(str.c_str(), "REG", 3) == 0){
            insert_criteria(str);
		} 
        // process rr start and end
        else if (strncmp(str.c_str(), "rr_start:", 9) == 0){
            
            std::string startRange = str.erase(0, 9);
            startRRInstrCount =  std::stoull(startRange, NULL);
            printf("Start rr instr count: %lu\n", startRRInstrCount);
        } else if  (strncmp(str.c_str(), "rr_end:", 7) == 0){
            std::string endRange = str.erase(0, 7);
            endRRInstrCount =  std::stoull(endRange, NULL);
            printf("end rr instr count: %lu\n", endRRInstrCount);
        } 
        // else if (strncmp(str.c_str(), "addr:", 4) == 0){
        //     startRange = startRange.erase(0, 4);
        //     start_addr = std::stoull(startRange, NULL, 16);
        //     end_addr = std::stoull(endRange, NULL, 16);
        //     printf("Start addr: %lx, end addr: %lx\n", start_addr, end_addr);
        // }   
    }
}

/**
 *  
 * 
 */ 
SliceVar get_slice_var(Value *v) {
    return std::make_pair(LLVM, (uint64_t)v);
}

int addr_to_tb(uint64_t addr){

	std::map<uint64_t, int>::iterator it = tb_addr_map.lower_bound(addr);
	it--;
	printf("FOund tb %d, addr %lx\n", it->second, it->first);
	return it->second;

}

void bitset2bytes(std::bitset<MAX_BITSET> &bitset, uint8_t bytes[]) {
    for (int i = 0; i < MAX_BITSET/8; i++){
        for (int j = 0; j < 7; j++){
            bytes[i] |= bitset[i*8 + j] << j;
        }
    }
}

void mark(traceEntry &t) {
    int bb_num = t.bb_num;
    int insn_index = t.inst_index;
    // printf("insn index %d\n", insn_index);
    assert(insn_index < MAX_BITSET);
    markedMap[std::make_pair(t.func, bb_num)].second[insn_index] = 1;
    printf("Marking %s, block %d, instruction %d. Func count %d\n", t.func->getName().str().c_str(), bb_num, insn_index, markedMap[std::make_pair(t.func, bb_num)].first);
}
 
bool is_ignored(StringRef funcName) {
    if (external_helper_funcs.count(funcName) || 
        funcName.startswith("record") || 
        funcName.startswith("llvm.memcpy") ||
        funcName.startswith("llvm.memset") ){
        return true;
    }
    return false;
}

// Find the index of a block in a function
int get_block_index(Function *f, BasicBlock *b) {
    int i = 0;
    for (Function::iterator it = f->begin(), ed = f->end(); it != ed; ++it) {
        if (&*it == b) return i;
        i++;
    }
    return -1;
}

//******************************************************************
// Slicing functions
//*****************************************************************

void insertAddr(std::set<SliceVar> &sliceSet, SliceVarType type, uint64_t dyn_addr, int numBytes){
    // printf("numBytes %d\n", numBytes);
    switch (type){
        case TGT:
            sliceSet.insert(std::make_pair(TGT, dyn_addr));
            break;
        case MEM:
            printf("Inserting ");
            for (int off = 0; off < numBytes; off++){
                printf("%lx ", dyn_addr+off);
                sliceSet.insert(std::make_pair(MEM, dyn_addr+off));
            }
            printf("\n");
            break;
        case IGNORE:
        default:
            printf("Warning: unhandled address entry type %d\n", type);
            break;
    }
}

void insertValue(std::set<SliceVar> &sliceSet, Value* v){
    if(!isa<Constant>(v)){
        sliceSet.insert(std::make_pair(LLVM, uint64_t(v)));
    }
}

void get_usedefs_Store(traceEntry &t,
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    StoreInst* SI = dyn_cast<StoreInst>(t.inst);
    assert(t.ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_STORE);
    assert(t.ple->llvmentry().has_address());
    assert(t.ple->llvmentry().has_num_bytes());
    assert(t.ple->llvmentry().has_addr_type());

    if (!SI->isVolatile()){

        insertAddr(defines, static_cast<SliceVarType>(t.ple->llvmentry().addr_type()), t.ple->llvmentry().address(), t.ple->llvmentry().num_bytes());
        insertValue(uses, SI->getValueOperand());
        // insertValue(uses, SI->getPointerOperand());
    }
};

void get_usedefs_Load(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    LoadInst* LI = dyn_cast<LoadInst>(t.inst);
    assert(t.ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_LOAD);
    assert(t.ple->llvmentry().has_address());
    assert(t.ple->llvmentry().has_num_bytes());
    assert(t.ple->llvmentry().has_addr_type());

    // Add the memory address to the uses list. 
    // Giri goes back and searches for the stores before this load. Maybe that's better? 

     // Whereas moyix's stuff differentiates addresses and registers when storing in use list
     // I'll do what moyix does for now....

    // inserts dynamic address into use list
    insertAddr(uses, static_cast<SliceVarType>(t.ple->llvmentry().addr_type()), t.ple->llvmentry().address(), t.ple->llvmentry().num_bytes());

    // insertValue(uses, LI);

    insertValue(defines, t.inst);
};

void get_usedefs_intrinsic_call(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines, StringRef func_name){

    CallInst* c = dyn_cast<CallInst>(t.inst);

    SmallVector<StringRef, 2> *matches = new SmallVector<StringRef, 2>();

    // Load instruction, handled as store 
    if (Regex("helper_([lb]e|ret)_ld(.*)_mmu_panda").match(func_name, matches)) {
        int size = -1;
        StringRef sz_c = matches[0][2];
        if (sz_c.endswith("q")) size = 8;
        else if (sz_c.endswith("l")) size = 4;
        else if (sz_c.endswith("w")) size = 2;
        else if (sz_c.endswith("b")) size = 1;
        else assert(false && "Invalid size in call to load");
        
        printf("helper func ld mem uses:");
        insertAddr(uses, MEM, t.ple->llvmentry().address(), size);

        //call looks like call i64 @helper_le_ldul_mmu_panda(%struct.CPUX86State* %0, i32 %tmp2_v19, i32 1, i64 3735928559)
        Value *load_addr = c->getArgOperand(1);

        // Only add load_addr LLVM val if we are tracking slice on pointers
        if (tainted_ptr) {
            insertValue(uses, load_addr);
        }

        insertValue(defines, t.inst);
    }
    else if (Regex("helper_([lb]e|ret)_st(.*)_mmu_panda").match(func_name, matches))  {
        int size = -1;
        StringRef sz_c = matches[0][2];
        if (sz_c.endswith("q")) size = 8;
        else if (sz_c.endswith("l")) size = 4;
        else if (sz_c.endswith("w")) size = 2;
        else if (sz_c.endswith("b")) size = 1;
        else assert(false && "Invalid size in call to store");
        
        printf("helper func st mem defines: ");
        insertAddr(defines, MEM, t.ple->llvmentry().address(), size);
        
        // call looks like @helper_le_stl_mmu_panda(%struct.CPUX86State* %0, i32 %tmp2_v17, i32 %tmp0_v15, i32 1 tmp2_v17

        Value *store_addr = c->getArgOperand(1);
        Value *store_val  = c->getArgOperand(2);
        // insertValue(uses, store_addr);
        insertValue(uses, store_val);
    }
    else if (func_name.startswith("llvm.memcpy")) {

        // Get memcpy size
        int bytes = 0;
        Value *bytes_ir = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Load first
        insertAddr(uses, static_cast<SliceVarType>(t.ple->llvmentry().addr_type()), t.ple->llvmentry().address(), bytes);

        // Now store
        insertAddr(defines, static_cast<SliceVarType>(t.ple->llvmentry().addr_type()), t.ple->llvmentry().address(), bytes);

        // Src/Dst pointers
        insertValue(uses, c->getArgOperand(0));
        insertValue(uses, c->getArgOperand(1));
        
    }
    else if (func_name.startswith("llvm.memset")) {

        int bytes = 0;
        Value *bytes_ir  = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Now store
        insertAddr(defines, static_cast<SliceVarType>(t.ple->llvmentry().addr_type()), t.ple->llvmentry().address(), bytes);

        // Dst pointer
        insertValue(uses, c->getArgOperand(0));

        // Value (if not constant)
        insertValue(uses, c->getArgOperand(1));
    } else if (func_name.equals("helper_outb") ||
             func_name.equals("helper_outw") ||
             func_name.equals("helper_outl")) {
        // We don't have any model of port I/O, so
        // we just ignore this one
    } else {
        // Add all args to the uses 

        printf("Num arg operands: %u\n", c->getNumArgOperands());
        insertValue(defines, c);    
        for (int i = 0; i < c->getNumArgOperands(); i++){
            insertValue(uses, c->getArgOperand(i));    
        }
    }

}


void get_usedefs_Call(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    CallInst* c = dyn_cast<CallInst>(t.inst);

    Function *subf = c->getCalledFunction();
    StringRef func_name = subf->getName();

    printf("CALL: pc = %lx (%lu), %s\n", t.ple->llvmentry().pc(), t.ple->llvmentry().pc(), func_name.data());
    Function::arg_iterator argIt;
    int argIdx;

    if (subf->isDeclaration() || subf->isIntrinsic()) {
        get_usedefs_intrinsic_call(t, uses, defines, func_name);
    } else {
        // call to some helper
        if (!c->getType()->isVoidTy()) {
            insertValue(defines, c);
        }
        // Uses the return value of that function.
        // Note that it does *not* use the arguments -- these will
        // get included automatically if they're needed to compute
        // the return value.
        uses.insert(std::make_pair(FRET, ret_ctr));
    }
    return;
};

void get_usedefs_Ret(traceEntry &t, 
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defines){

    printf("RETURN: pc = %lx (%lu)\n", t.ple->llvmentry().pc(), t.ple->llvmentry().pc());
    // t.inst->print(outs());
    
    ReturnInst *r = cast<ReturnInst>(t.inst);
    Value *v = r->getReturnValue();
    if (v != NULL) insertValue(uses, v);

    defines.insert(std::make_pair(FRET, ret_ctr++));
};

void get_usedefs_PHI(traceEntry &t, 
    std::set<SliceVar> &uses, 
    std::set<SliceVar> &defines){
    assert(t.ple->llvmentry().phi_index());
    
    PHINode *p = cast<PHINode>(t.inst);
    
    Value *v = p->getIncomingValue(t.ple->llvmentry().phi_index());
    insertValue(uses, v);
    insertValue(defines, t.inst); 
};

void get_usedefs_Select(traceEntry &t, 
std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    SelectInst *si = cast<SelectInst>(t.inst);
    printf("SELECT ");
    
    if (t.ple->llvmentry().condition()){
        printf("condition: %d, True value", t.ple->llvmentry().condition());
        // if condition is true, choose the first select val
       insertValue(uses, si->getTrueValue()); 
    } else {
        // if condition is true, choose the first select val
       insertValue(uses, si->getFalseValue()); 
    }
    insertValue(defines, t.inst); 
};

void get_usedefs_Br(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){
    BranchInst *bi= dyn_cast<BranchInst>(t.inst);

    //XXX: Use condition...
    if (bi->isConditional()){
        insertValue(uses, bi->getCondition());
    }
}

void get_usedefs_Switch(traceEntry &t, 
        std::set<SliceVar> &uses, 
        std::set<SliceVar> &defines){

    //XXX: Use condition...
    SwitchInst *si = dyn_cast<SwitchInst>(t.inst);
    insertValue(uses, si->getCondition());
}

void get_usedefs_default(traceEntry &t, std::set<SliceVar> &uses, std::set<SliceVar> &defines){
    // by default, add all operands to uselist
    for (User::op_iterator op = t.inst->op_begin(); op != t.inst->op_end(); op++){
        Value *v = *op;
        
        //XXX: May no longer need to check for BB anymore, since we handle br and switch separately now. 
        if (!dyn_cast<BasicBlock>(v)){
            insertValue(uses, v);
        }
    }
    insertValue(defines, t.inst);
}

void get_uses_and_defs(traceEntry &te, std::set<SliceVar> &uses, std::set<SliceVar> &defs) {
    // std::cout << t.target_asm << std::endl;
    if (te.ple != NULL && te.ple->has_llvmentry() && te.ple->llvmentry().pc() != last_pc) {
        printf("\n>>>>>>>>>>>NEW PC: %lx (%lu)\n", te.ple->llvmentry().pc(), te.ple->llvmentry().pc());
        last_pc = te.ple->llvmentry().pc();
    }

    printf("usedefs inst_index %d\n", te.inst_index);

    switch (te.inst->getOpcode()) {
        case Instruction::Store:
            printf("STORE: pc = %lx (%lu), val = %lx(%lu)\n", te.ple->llvmentry().pc(), te.ple->llvmentry().pc(), te.ple->llvmentry().value(), te.ple->llvmentry().value());

            // Check if we are storing to PC

            // if (te.ple->llvmentry().address() == cpustatebase +8*4) {
            //     // Check if we marked an instruction before 
            //     if (cur_vma == "extlibcalls" && markedInsideBB) {
            //         printf("STORING TO EIP IN CALL\n");
            //         mark(te);
            //         markedInsideBB = false;
            //     }
            // }

            get_usedefs_Store(te, uses, defs);
            return;
        case Instruction::Load:
            printf("LOAD: pc = %lx (%lu), val = %lx(%lu)\n", te.ple->llvmentry().pc(), te.ple->llvmentry().pc(), te.ple->llvmentry().value(), te.ple->llvmentry().value());
            get_usedefs_Load(te, uses, defs);
            return;
        case Instruction::Call:
            get_usedefs_Call(te, uses, defs);
            return;
        case Instruction::Ret:
            get_usedefs_Ret(te, uses, defs);
            return;
        case Instruction::PHI:
            get_usedefs_PHI(te, uses, defs);
            return;
        case Instruction::Select:
            get_usedefs_Select(te, uses, defs);
            return;
        case Instruction::Unreachable: // how do we even get these??
            return;
        case Instruction::Br:
            get_usedefs_Br(te, uses, defs);
            return;
        case Instruction::Switch:
            get_usedefs_Switch(te, uses, defs);
            return;
        case Instruction::BitCast:
        {
            CastInst *BC = dyn_cast<CastInst>(te.inst);
            if (IntegerType *IT = dyn_cast<IntegerType>(BC->getDestTy())){
                if (IT->getBitWidth() == 8){
                    return;
                }
            }
            get_usedefs_default(te, uses, defs);
            return;
        }
        case Instruction::ZExt:     
        {
            ZExtInst *Z = dyn_cast<ZExtInst>(te.inst);
            if (IntegerType *IT = dyn_cast<IntegerType>(Z->getDestTy())){
                if (IT->getBitWidth() == 64){
                    return;
                }
            }
            get_usedefs_default(te, uses, defs);
            return;
        }    
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::UDiv:
        case Instruction::URem:
        case Instruction::SDiv:
        case Instruction::SRem:
        case Instruction::IntToPtr:
        case Instruction::PtrToInt:
        case Instruction::And:
        case Instruction::Xor:
        case Instruction::Or:
        case Instruction::SExt:
        case Instruction::Trunc:
        case Instruction::GetElementPtr: // possible loss of precision
        case Instruction::ExtractValue:
        case Instruction::InsertValue:
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr:
        case Instruction::ICmp:
        case Instruction::FCmp:
        case Instruction::Alloca:
            get_usedefs_default(te, uses, defs);
            return;
        default:
            printf("Note: no model for %s, assuming uses={operands} defs={lhs}\n", te.inst->getOpcodeName());
            // Try "default" operand handling
            // defs = LHS, right = operands

            get_usedefs_default(te, uses, defs);
            return;
    }
    return;
}

// Return depth of def in worklist, if found
// else -1
int inWorklist(std::set<std::pair<SliceVar, int>>& workset, const SliceVar &def) {
    for (auto& pair: workset) {
        if (pair.first == def) {
            return pair.second;
        }
    }

    return -1;
}

//TODO: Don't need to store the func in every single traceEntry, only in the first entry of every function. The name suffices for mark function otherwise

/*
 * This function takes in a list of criteria
 * and iterates backwards over an LLVM function
 * updating the global work_list, uses, and defs. 
 * 
 * Return true if block is marked, false otherwise
 */
bool slice_trace(std::vector<traceEntry> &aligned_block){

    std::cout << "aligned block size " << aligned_block.size() << "\n";
 
    std::stack<std::map<SliceVar, SliceVar>> argMapStack;
    Function *entry_tb_func = aligned_block[0].func;
    bool is_block_marked = false;
    
    //print out aligned block for debugging purposes
    for (std::vector<traceEntry>::reverse_iterator traceIt = aligned_block.rbegin() ; traceIt != aligned_block.rend(); ++traceIt) {
        std::set<SliceVar> uses, defs;
        get_uses_and_defs(*traceIt, uses, defs);

        printf("INST: %s\n", Instruction::getOpcodeName(traceIt->inst->getOpcode()));
        //XXX: For some reason, these values are kinda corrupted. Should checkout what's wrong.  
        //printf("rr instr: %lx\n", traceIt->ple->pc());

        // printf("DEBUG: %lu defs, %lu uses\n", defs.size(), uses.size());
        printf("DEFS: ");
        print_set(defs);
        printf("USES: ");
        print_set(uses);
        
        //update work_list
        
        // if we are in a subfunction, map uses through argument map
        // meaning, see if any uses in our work_list are derived from an argument of this function
        // if so, replace use in work_list with function arg
        if (traceIt->func != entry_tb_func){
            // get most recent argMap off of argStack
            std::map<SliceVar, SliceVar> subfArgMap = argMapStack.top();
            
            // printf("Uses_it");
            // print_set(uses);
            for (auto usesIt = uses.begin(); usesIt != uses.end(); ){
                auto argIt = subfArgMap.find(*usesIt);
                if (argIt != subfArgMap.end()){
                    printf("Mapping uses through argList\n");
                    // replace value in uses list with argument value
                    uses.erase(usesIt++);
                    uses.insert(argIt->second); 
                    printf("NEW USES: ");
                    print_set(uses);
                } else {
                    usesIt++;
                }
            }
        }
        
        //update work_list
        // for each element in work_list, see if it is in the defs list
        // if it is, then remove it from the work_list and replace it with its uses from the uses list
        if (traceIt->inst->isTerminator() && !isa<ReturnInst>(traceIt->inst)){
            // mark(*traceIt);
            // printf("INSERTING BRANCH USES INTO WORK_lIST\n");
            // work_list.insert(uses.begin(), uses.end());
        } else {
            bool scn_edge = false;
            for (auto &def : defs) {
                // Check all SliceVars' worklists 
                
                for (auto& slice_set: slice_work_lists) {

                    int depth; 
                    if ((slice_set.second.second.count(def)) > 0) {
                        // If one of the defs is in worklist
                        depth = slice_set.second.second.at(def);

                        is_block_marked = true;

                        // print debug info
                        char destbuf[200] = {};
                        int destoff = 0;
                        for (const SliceVar &w : defs) {
                            int ct = snprintf(destbuf+destoff, 30, "%s ", slicevar_to_str(w).c_str());
                            destoff += ct;
                        }

                        char usebuf[200] = {};
                        int off = 0;
                        for (const SliceVar &w : uses) {
                            int ct = snprintf(usebuf+off, 30, "%s ", slicevar_to_str(w).c_str());
                            off += ct;
                        }

                        printf("DEFINED %s, adding %s to %s work_list\n", destbuf, usebuf, slicevar_to_str(slice_set.first).c_str());
                        mark(*traceIt);

                        // Increment SCN based on type of instruction
                        switch (traceIt->inst->getOpcode()) {
                            case Instruction::LShr:
                            case Instruction::AShr:
                            case Instruction::Shl:
                            case Instruction::Mul:
                            case Instruction::FMul:
                            case Instruction::Add:
                            case Instruction::UDiv:
                            case Instruction::SDiv:
                            case Instruction::FDiv:
                            case Instruction::FSub:
                            case Instruction::FAdd:
                            case Instruction::URem:
                            case Instruction::SRem:
                            case Instruction::FRem:
                                // mixed; i.e. operation is not bitwise, so taint transfers
                                // between bytes in the word.
                            case Instruction::And:
                            case Instruction::Or:
                            case Instruction::Xor:
                            {
                                // set SCN to be the maximum depth of old SCN and depth of new SCN

                                int old_scn = slice_set.second.first;
                                slice_set.second.first = std::max(depth+1, old_scn);
                                printf("SCN depth: %d -> %d for %s\n", old_scn, slice_set.second.first, slicevar_to_str(slice_set.first).c_str());

                                scn_edge = true;

                                // let's create a new graph with just SCN nodes 
                                // for (const SliceVar &w : uses) {

                                //     vertex_t scn_use_v;
                                //     scn_use_v = boost::add_vertex(scn_g);   
                                //     scn_g[scn_use_v].slice_var = slicevar_to_str(w);
                                //     scn_g[scn_use_v].slice_var_type = w.first;
                                //     scn_g[scn_use_v].opcode = get_opcode(*traceIt);

                                //     scn_vertex_table[w] = scn_use_v;

                                //     vertex_t scn_def_v = scn_vertex_table.at(def);
                                //     boost::add_edge(scn_use_v, scn_def_v, scn_g);
                                // }

                                break;
                            }
                            default:
                                // don't increment scn
                                // printf("Instr %s no scn\n", Instruction::getOpcodeName(traceIt->inst->getOpcode()));
                                ;
                            }

                        slice_set.second.second.erase(def);

                        // increase count for this LLVM instr
                        slice_count[slice_set.first][traceIt->inst->getOpcode()]++;

                        // generate a graph node for this marked instr 
                        // create vertices for the uses, which will have directed edges to the def 
                        for (const SliceVar &w : uses) {
                            // If the use is not ESP or EBP, insert use into work_list
                            if (slicevar_to_str(w).find("ESP") == std::string::npos && slicevar_to_str(w).find("EBP") == std::string::npos) {

                                // insert {use, depth} into slice_set
                                slice_set.second.second.insert({w, slice_set.second.first});

                                vertex_t use_v;
                                if (vertex_table.find(w) != vertex_table.end()) {
                                    use_v = vertex_table[w];
                                } else {
                                    use_v = boost::add_vertex(g);   
                                    g[use_v].slice_var = slicevar_to_str(w);
                                    g[use_v].slice_var_type = w.first;
                                    // g[use_v].opcode = get_opcode(*traceIt);
                                    // if ( traceIt->ple != NULL && traceIt->ple->has_llvmentry() && traceIt->ple->llvmentry().has_value() ) {

                                    //     uint64_t val = traceIt->ple->llvmentry().value();

                                    //     printf("node value %lx\n", val);
                                    
                                    //     g[use_v].value = traceIt->ple->llvmentry().value();
                                    // }
                                }

                                // Add to vertex lookup table
                                vertex_table[w] = use_v;

                                // if def only has one outgoing edge, try condensing use to def 
                                vertex_t def_v = vertex_table.at(def);
                                g[def_v].opcode = get_opcode(*traceIt);
                                if ( traceIt->ple != NULL && traceIt->ple->has_llvmentry() && traceIt->ple->llvmentry().has_value() ) {

                                    uint64_t val = traceIt->ple->llvmentry().value();

                                    printf("node value %lx\n", val);
                                
                                    g[def_v].value = traceIt->ple->llvmentry().value();
                                }
                                // unsigned out_degree = (unsigned)boost::out_degree(def_v, g);
                                
                                // if (out_degree == 1) {
                                //     auto p = out_edges(def_v, g);
                                //     auto edge = *p.first;
                                    
                                //     vertex_t next_def_v = target(edge, g);
                                //     // g[next_def_v].slice_var += " condensed";
                                //     boost::add_edge(use_v, next_def_v, g);                                    
                                // } else {
                                    // add edge from use to def 
                                
                                // if (scn_edge) {
                                    
                                boost::add_edge(use_v, def_v, g);
                                if (scn_edge) {
                                    printf("boost adding SCN edge\n");
                                    g[use_v].scn = true;
                                }

                                // }
                                // }
                            }
                        }

                        print_slice_worklist(slice_work_lists);

                        break;
                    }
                }   
            }
        }

        // in align_function, we put the Call traceEntry after the function's instructions and return
        // So, we'll see this Call before we descend backwards into the function
        if (CallInst *c = dyn_cast<CallInst>(traceIt->inst)) {
            std::map<SliceVar, SliceVar> argMap;
            Function *subf = c->getCalledFunction();

            if (!is_ignored(subf->getName())) {
                int argIdx;
                Function::arg_iterator argIt;
                for (argIt = subf->arg_begin(), argIdx = 0; argIt != subf->arg_end(); argIt++, argIdx++) {
                    argMap[get_slice_var(&*argIt)] = get_slice_var(c->getArgOperand(argIdx));
                    printf("argMap %s => %s\n", slicevar_to_str(get_slice_var(&*argIt)).c_str(), slicevar_to_str(get_slice_var(c->getArgOperand(argIdx))).c_str());
                    // printf("argit\n");
                    // argIt->dump();
                    // c->getArgOperand(argIdx)->dump();
                }

                argMapStack.push(argMap);
            }

        } else if (&*(traceIt->func->getEntryBlock().begin()) == &*(traceIt->inst)) {
            // if first instruction of subfunction's entry block
            // pop the stack before we return to calling parent
            if (!argMapStack.empty()) {
                argMapStack.pop();
            }
        }

        // printf("Work_list: ");
        // print_set(work_list);
    }

    return is_block_marked;
}

bool in_exception = false;

//******************************************************************
// Alignment functions
//*****************************************************************

int align_intrinsic_call(std::vector<traceEntry> &aligned_block, traceEntry t, std::vector<panda::LogEntry*>& ple_vector, StringRef func_name, int cursor_idx){
    
    panda::LogEntry* ple = ple_vector[cursor_idx];

    if (Regex("helper_([lb]e|ret)_ld.*_mmu_panda").match(func_name)) {
        assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_LOAD);

        t.ple = ple;

        aligned_block.push_back(t);
        cursor_idx++;
    } else if (Regex("helper_([lb]e|ret)_st.*_mmu_panda").match(func_name) || func_name.startswith("llvm.memset")) {
        assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_STORE);

        t.ple = ple;
          
        aligned_block.push_back(t);
        cursor_idx++;
    } else if (func_name.startswith("llvm.memcpy")) {
        assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_LOAD);

        panda::LogEntry* storePle = ple_vector[cursor_idx+1];
        assert(storePle && storePle->llvmentry().type() == FunctionCode::FUNC_CODE_INST_STORE);
        
        t.ple = ple;
        t.ple2 = storePle;

        aligned_block.push_back(t);
        cursor_idx += 2;
    } else {
        t.ple = new panda::LogEntry();;

        aligned_block.push_back(t);

        // Don't increment cursor idx for these intrinsics
    }

    // Otherwise, don't add an entry?
    return cursor_idx;
}


/*
 * Takes vector of log entries and aligns them with llvm Instructions from function
 * then places them in aligned_block
 * 
 *
 */
int align_function(std::vector<traceEntry> &aligned_block, llvm::Function* f, std::vector<panda::LogEntry*>& ple_vector, int cursor_idx){
    
    printf("f getname %s\n", f->getName().str().c_str());

    //print_set(work_list);

    BasicBlock &entry = f->getEntryBlock();
    BasicBlock *next_block = &entry;

    bool has_successor = true;
    while (has_successor) {
        has_successor = false;
        
        int inst_index = 0;

        for (BasicBlock::iterator i = next_block->begin(), e = next_block->end(); i != e; ++i) {

            traceEntry t;
            t.bb_num = get_block_index(f, next_block);
            t.inst_index = inst_index;
            t.inst = i;
            t.func = f;     

            inst_index++;

            std::string target_asm = "";
            bool target_asm_seen, target_asm_marked = false;
            if (MDNode* N = i->getMetadata("target_asm")){
                // if (!target_asm.empty()){
                target_asm = cast<MDString>(N->getOperand(0))->getString();
                //printf("%lx ", base_addr);
                //base_addr += target_asm.length()/2;
                print_target_asm(dcr, target_asm, target_asm_marked, 0);
                t.target_asm = target_asm;
                // }                    
                
                // updated target_asm
                target_asm = cast<MDString>(N->getOperand(0))->getString();
                target_asm_seen = false;
                target_asm_marked = false;
            }

            if (in_exception) return cursor_idx;

            panda::LogEntry* ple;
            if (cursor_idx >= ple_vector.size()){
                ple = NULL;
            } else {
                ple = ple_vector[cursor_idx];
            }

            // Peek at the next thing in the log. If it's an exception, no point
            // processing anything further, since we know there can be no dynamic
            // values before the exception.
            if (ple && ple->llvmentry().type() == LLVM_EXCEPTION) {
                printf("Found exception, will not finish this function.\n");
                in_exception = true;
                cursor_idx++;
                return cursor_idx;
            }

            switch (i->getOpcode()){
                case Instruction::Load: {
                    // get the value from the trace 
                    assert (ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_LOAD);
                    t.ple = ple;

                    cursor_idx++;
                    aligned_block.push_back(t);
                    break;
                }
                case Instruction::Store: {
                    StoreInst *s = cast<StoreInst>(i);
                    if (s->isVolatile()){
                        break;
                    }

                    assert (ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_STORE);
                    t.ple = ple;

                    cursor_idx++;
                    aligned_block.push_back(t);
                    break;
                }
                case Instruction::Br: {

                    //Check that this entry is a BR entry
                    assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_BR);

                    //std::unique_ptr<panda::LogEntry> new_dyn (new panda::LogEntry);
                    //new_dyn->set_allocated_llvmentry(new panda::LLVMEntry());

                    //t.ple = new_dyn.get();

                    //update next block to examine
                    has_successor = true;
                    BranchInst *b = cast<BranchInst>(&*i);
                    next_block = b->getSuccessor(!(ple->llvmentry().condition()));
                    // printf("Condition %d\n", !(ple->llvmentry().condition()));
                    // next_block->dump();

                    aligned_block.push_back(t);
                    
                    panda::LogEntry *bbPle = ple_vector[cursor_idx+1];
                    assert(bbPle && bbPle->llvmentry().type() == FunctionCode::BB);

                    cursor_idx+=2;
                    break;
                }
                case Instruction::Switch: {
                    //Check that current entry is a startBB entry
                    assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_SWITCH);

                    //std::unique_ptr<panda::LogEntry> new_dyn (new panda::LogEntry);
                    //new_dyn->set_allocated_llvmentry(new panda::LLVMEntry());
                    //t.ple = new_dyn.get();
                    
                    aligned_block.push_back(t);

                    //update next block to examine
                    SwitchInst *s = cast<SwitchInst>(&*i);
                    unsigned width = s->getCondition()->getType()->getPrimitiveSizeInBits();
                    IntegerType *intType = IntegerType::get(getGlobalContext(), width);
                    ConstantInt *caseVal = ConstantInt::get(intType, ple->llvmentry().condition());
                    
                    has_successor = true;
                    SwitchInst::CaseIt caseIndex = s->findCaseValue(caseVal);
                    next_block = s->getSuccessor(caseIndex.getSuccessorIndex());
                    //next_block->dump();

                    panda::LogEntry *bbPle = ple_vector[cursor_idx+1];
                    assert(bbPle && bbPle->llvmentry().type() == FunctionCode::BB);
                    
                    cursor_idx+=2;
                    break;
                }
                case Instruction::PHI: {
                    
                    // We don't actually have a dynamic log entry here, but for
                    // convenience we do want to know which basic block we just
                    // came from. So we peek at the previous non-PHI thing in
                    // our trace, which should be the predecessor basic block
                    // to this PHI
                    PHINode *p = cast<PHINode>(&*i);
                    printf("Found a PHI INSTRUCTION\n");

                    panda::LogEntry* new_dyn  = new panda::LogEntry();
                    new_dyn->mutable_llvmentry()->set_phi_index(-1);
                    new_dyn->mutable_llvmentry()->set_pc(-1);

                    // Find the last non-PHI instruction
                    // Search from Reverse beginning (most recent traceEntry) 
                    for (auto sit = aligned_block.rbegin(); sit != aligned_block.rend(); sit++) {
                        if (sit->inst->getOpcode() != Instruction::PHI) {
                            new_dyn->mutable_llvmentry()->set_phi_index(p->getBasicBlockIndex(sit->inst->getParent()));
                            break;
                        }
                    }
                    t.ple = new_dyn;
                    aligned_block.push_back(t);
                    //cursor_idx++;
                    break;
                }
                case Instruction::Select: {
                    assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_SELECT);

                    t.ple = ple;

                    aligned_block.push_back(t);
                    cursor_idx++;
                    break;
                }
                case Instruction::Ret: {
                    assert(ple && ple->llvmentry().type() == FunctionCode::FUNC_CODE_INST_RET);

                    //XXX: Create log entry here for return value
                    t.ple = ple;
                    aligned_block.push_back(t);

                    cursor_idx++;
                    break;
                }
                case Instruction::Call: {
                    //update next block to be inside calling function. 
                    CallInst *call = cast<CallInst>(&*i);
                    Function *subf = call->getCalledFunction();
                    assert(subf != NULL);
                    StringRef func_name = subf->getName();
                
                    if (func_name.startswith("record")){
                            // ignore
                    } else if (subf->isDeclaration() || subf->isIntrinsic()) {

                        cursor_idx = align_intrinsic_call(aligned_block, t, ple_vector,func_name, cursor_idx);
                    } else {
                        // descend into function
                        
                        panda::LogEntry *bbPle = ple_vector[cursor_idx];
                        assert(bbPle && bbPle->llvmentry().type() == FunctionCode::BB);
                        
                        printf("descending into function, cursor_idx= %d\n", cursor_idx+1);
                        cursor_idx = align_function(aligned_block, subf, ple_vector, cursor_idx+1);
                        printf("Returned from descend, cursor_idx= %d\n", cursor_idx);

                        panda::LogEntry *callPle = ple_vector[cursor_idx];
                        assert(callPle && callPle->llvmentry().type() == FunctionCode::FUNC_CODE_INST_CALL);
                        cursor_idx += 1;
                        
                        // call is placed after the instructions of the called function
                        // so slice_trace will know 
                        t.ple = callPle;
                        aligned_block.push_back(t);
                    }
                    break;
                }
                default:
                    //printf("fell through!\n");
                    /*print_insn(i);*/
                    if (!i->getMetadata("host")) {
                        aligned_block.push_back(t);
                    }
                    break;

            }
        }
    }       
    return cursor_idx;
    // Iterate every instruction to find its uses and its definition
    // if one of the definitions is in the working list (which contains initial criterion)
    // update working list with the uses 

    //update work_list 
    /*for (auto it )*/
}

//******************************************************************
// Driver functions 
//*****************************************************************

void usage(char *prog) {
   fprintf(stderr, "Usage: %s [OPTIONS] <llvm_mod> <dynlog> <criteria_file>\n",
           prog);
   fprintf(stderr, "Options:\n"
           "  -d                : enable debug output\n"
           "  -o OUTPUT         : save slice results to OUTPUT\n"
           "  <llvm_mod>        : the LLVM bitcode module\n"
           "  <dynlog>          : the pandalog trace file\n"
           "  <criteria_file> ...   : the slicing criteria, i.e., what to slice on\n"
          );
}

int main(int argc, char **argv){
    //parse args 

    if (argc < 4) {
        printf("Usage: <llvm-mod.bc> <trace-file> <criteria-file>\n");
        return EXIT_FAILURE; 
    }

    FILE *coverageFile = fopen("coverage", "wb");

    int opt, debug;
    unsigned long num, pc;
    bool show_progress = false;
    bool have_num = false, have_pc = false;
    bool print_work = false;
    bool align_only = false;
    const char *output = NULL;
     
    while ((opt = getopt(argc, argv, "to:")) != -1) {
        switch (opt) {
        case 't':
            tainted_ptr = true;
            break;
        case 'o':
            output = optarg;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    char *llvm_mod_fname = argv[optind];
    printf("llvm_mod_fname %s\n", llvm_mod_fname);
    char *llvm_trace_fname = argv[optind+1];
    char *criteria_fname = argv[optind+2];

    // Maintain a working set 
    // if mem, search for last occurrence of that physical address  

    llvm::LLVMContext &ctx = llvm::getGlobalContext();
    llvm::SMDiagnostic err;
    mod = llvm::ParseIRFile(llvm_mod_fname, err, ctx);
    
    LLVMInitializeAllAsmPrinters();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllDisassemblers();

    dcr = LLVMCreateDisasm (
        "i386-unknown-linux-gnu",
        NULL,
        0,
        NULL,
        NULL
    );

    LLVMSetDisasmOptions(dcr, 4); 

	GlobalVariable* cpuStateAddr = mod->getGlobalVariable("CPUStateAddr");
	cpuStateAddr->dump();
	ConstantInt* constInt = cast<ConstantInt>( cpuStateAddr->getInitializer());
	cpustatebase = constInt->getZExtValue();

    printf("EAX: %lx\n", cpustatebase + 0*4);
    printf("ECX: %lx\n", cpustatebase + 1*4);
    printf("EDX: %lx\n", cpustatebase + 2*4);
    printf("EBX: %lx\n", cpustatebase + 3*4);
    printf("ESP: %lx\n", cpustatebase + 4*4);
    printf("EBP: %lx\n", cpustatebase + 5*4);
    printf("ESI: %lx\n", cpustatebase + 6*4);
    printf("EDI: %lx\n", cpustatebase + 7*4);
    printf("EIP: %lx\n", cpustatebase + 8*4);

	// Populate map of addrs to tb_nums
	int tb_num;
	uint64_t addr;
	for (auto curFref = mod->getFunctionList().begin(), 
              endFref = mod->getFunctionList().end(); 
              curFref != endFref; ++curFref){
		if (strncmp(curFref->getName().str().c_str(), "tcg-llvm-tb", 11) == 0){
			sscanf(curFref->getName().str().c_str(), "tcg-llvm-tb-%d-%lx", &tb_num, &addr); 
			tb_addr_map[addr] = tb_num;
		}
	}

    // Add the slicing criteria from the file
    process_criteria(criteria_fname);

    // Initialize the lookup table and Graph with the initial worklist
     for (auto swl : slice_work_lists) {
        printf("Creating graph node for Var: %s\n", slicevar_to_str(swl.first).c_str());
        vertex_t v = boost::add_vertex(g);
        g[v].slice_var = slicevar_to_str(swl.first);
        g[v].slice_var_type = -1;
        g[v].opcode = 0;
        vertex_table[swl.first] = v;

        vertex_t scn_v = boost::add_vertex(scn_g);
        scn_g[scn_v].slice_var = slicevar_to_str(swl.first);
        scn_g[scn_v].slice_var_type = -1;
        scn_g[scn_v].opcode = 0;
        scn_vertex_table[swl.first] = scn_v;
    } 

    printf("Starting work_list: ");
    print_slice_worklist(slice_work_lists);

    if (output == NULL) {
        output = "slice_report.bin";
        fprintf(stderr, "Note: no output file provided. Will save results to '%s'\n", output);
    }

    printf("Slicing trace\n");
    /*pandalog_open_read_bwd(llvm_trace_fname);*/
    
    //Panda__LogEntry *ple;

    std::vector<panda::LogEntry*> ple_vector;   
    std::vector<traceEntry> aligned_block;
    
    PandaLog p;
    printf("Opening logfile %s for read\n", argv[2]);
    p.open_read_bwd((const char *) argv[2]);
    std::unique_ptr<panda::LogEntry> ple;
    panda::LogEntry* ple_raw;

	int startSlicing = 0;

    // Process by the function? I'll just do the same thing as dynslice1.cpp for now.

    while ((ple = p.read_entry()) != NULL) {
        // while we haven't reached beginning of file yet 
        char namebuf[128];
        
        // If we're not in the slicing range specified in criteria file
        if (ple->instr() > endRRInstrCount || ple->instr() < startRRInstrCount){
            continue;
        }

        // If not a !host metadata instr
        ple_vector.push_back(new panda::LogEntry(*ple.get()));

        // If we have found the start of an LLVM function
        if (ple->llvmentry().type() == FunctionCode::LLVM_FN && ple->llvmentry().tb_num()) {
            if (ple->llvmentry().tb_num() == 0) {
                break;
            }

            int cursor_idx = 0;
            sprintf(namebuf, "tcg-llvm-tb-%lu-%lx", ple->llvmentry().tb_num(), ple->pc());
            Function *f = mod->getFunction(namebuf);
            
            assert(f != NULL);
            
            //Check if this translation block is complete -- that is, if it ends with a return marker
            if (ple_vector[0]->llvmentry().type() != FunctionCode::FUNC_CODE_INST_RET){
                printf("WARNING: BB %s CUT SHORT BY EXCEPTION!\n", namebuf);
                printf("ple_vector size %lu\n", ple_vector.size());
                aligned_block.clear();
                ple_vector.clear();
                continue;
            }

            // If block is marked as an interrupt, exception, etc.
            //printf("Flags: %x\n", ple->llvmentry().flags());
			if(ple->llvmentry().flags() & 1) {
                //printf("BB is an interrupt, skipping\n");
				ple_vector.clear();
                aligned_block.clear();
                continue;
			}

            //If we are not in the list of libraries/vmas of interest
            std::string module_name = ple->llvmentry().vma_name();
            // cur_vma = module_name;
            printf("lib_name: %s\n", module_name.c_str());

            if (searchModules.find(module_name) == searchModules.end()){
                // if can't find module in list of modules from criteria
                // clear vector
                ple_vector.clear();
                aligned_block.clear();
                continue;
            }
            
            printf("\n************************************************\n********** %s instr: %lu **********\n************************************************\n", namebuf, ple->instr());

            // Generate coverage 
            base_addr_map[module_name] = ple->llvmentry().vma_base();
            fprintf(coverageFile, "%s:%lx\n", module_name.c_str(), ple->pc());

            std::reverse(ple_vector.begin(), ple_vector.end());
            
            assert(ple_vector[0]->llvmentry().type() == FunctionCode::LLVM_FN && ple_vector[1]->llvmentry().type() == FunctionCode::BB);

            //Skip over first two entries, LLVM_FN and BB
            ple_vector.erase(ple_vector.begin(), ple_vector.begin()+2);

            cursor_idx = align_function(aligned_block, f, ple_vector, cursor_idx);
			bool is_block_marked = slice_trace(aligned_block);

            printf("After slice trace\n");
            print_slice_worklist(slice_work_lists);

            // If we added to the worklist, increase hitcount for this bb/function
            if (is_block_marked){
                markedMap[std::make_pair(f, 1)].first += 1;
                printf("Func hitcount %d\n", markedMap[std::make_pair(f, 1)].first);

            }

            aligned_block.clear();
            ple_vector.clear();
        }
    }

   print_slice_worklist(slice_work_lists);
   for (auto slice_set: slice_work_lists) {
        std::cout << slicevar_to_str(slice_set.first) << ": ";
       print_slice_count(slice_count[slice_set.first]);
   }


   printf("Done slicing. Marked %lu blocks\n", markedMap.size()); 

   // Write base addrs of coverage
   for (auto it = base_addr_map.begin(); it != base_addr_map.end(); it++) {
        fprintf(coverageFile, "base:%s:%lx\n", it->first.c_str(), it->second);
   }

   FILE *outf = fopen(output, "wb");
   for (auto &markPair: markedMap) {
        uint32_t name_size = 0;
        uint32_t lib_size = 0;
        uint32_t bb_idx = markPair.first.second;
        uint32_t hit_count = markPair.second.first;
        uint8_t bytes[MAX_BITSET/8] = {};

        StringRef func_name = markPair.first.first->getName();
        name_size = func_name.size();
        bitset2bytes(markPair.second.second, bytes);

        fwrite(&name_size, sizeof(uint32_t), 1, outf);
        fwrite(func_name.str().c_str(), name_size, 1, outf);
        fwrite(&bb_idx, sizeof(uint32_t), 1, outf);
        fwrite(&hit_count, sizeof(uint32_t), 1, outf);
        fwrite(bytes, MAX_BITSET / 8, 1, outf);

   }

   std::cout << "Writing graphviz to out.dot" << std::endl;


   // remove all vertices with no edges 
   // typedef graph_traits<Graph>::vertex_iterator vertex_iter;
   // std::pair<vertex_iter, vertex_iter> vp;
   // for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
   //      if (degree(*vp.first, g) == 0) {
   //          printf("Has no edges, removing\n");
   //          remove_vertex(*vp.first, g);
   //      }
   // }

   // condense all trunc, zext, sext vertices: remove them, reroute input vertices to output vertex 
   typedef graph_traits<Graph>::vertex_iterator vertex_iter;
   typedef boost::graph_traits<Graph>::out_edge_iterator out_edge_iterator;
   typedef boost::graph_traits<Graph>::in_edge_iterator in_edge_iterator;
   std::pair<vertex_iter, vertex_iter> vp;

   for (vp = vertices(g); vp.first != vp.second; ++vp.first) {
        vertex_t this_v = *vp.first;
        unsigned opcode = g[this_v].opcode;
        if (opcode == Instruction::Trunc || opcode == Instruction::SExt || opcode == Instruction::ZExt) {

            // get single inputnodes 
            std::pair<in_edge_iterator, in_edge_iterator> in_it = in_edges(this_v, g);

            // for (in_it = in_edges(this_v, g); in_it.first != in_it.second; ++in_it.first) {
                vertex_t src_v = source(*in_it.first, g);    
                
            // }

            // get all output nodes
            std::pair<out_edge_iterator, out_edge_iterator> outit = out_edges(this_v, g);
            for (outit = out_edges(this_v, g); outit.first != outit.second; ++outit.first) {
                vertex_t targ_v = target(*outit.first, g);    
                add_edge(src_v, targ_v, g); 
            }
            
            clear_vertex(this_v, g);
            remove_vertex(this_v, g);
        }
   }

   std::ofstream outgraph("out.dot");
   // print_graph(g, "test");
    myVertexWriter<Graph> my_vwriter(g);
    // boost::write_graphviz(outgraph, g, make_label_writer(get(&Vertex::slice_var, g)));
    boost::write_graphviz(outgraph, g, my_vwriter);

    p.close();
    return 0;
}





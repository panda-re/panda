// This plugin logs the N calls to the functions in asids.
// Then extracts and logs synthetic information about the called functions, including memory access information.

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "panda/tcg-llvm.h"
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/InstrTypes.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <map>
#include <set>
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#include <bits/stdc++.h> 
#include <algorithm>

#include <stdio.h>
#include "json.hpp"
#include <cctype>
#include <regex>
#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#include "ShannonEntropyTest.hpp"

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

// ############ llvm_visiting ############
#include <inttypes.h>
#include <stdint.h>
// ############ llvm_visiting ############

extern "C" {
  bool init_plugin(void *);
  void uninit_plugin(void *);
}

using namespace std;
using Asid = target_ulong;
using Address = target_ulong;
using Funid = std::pair<Asid, Address>;
static std::ofstream outfstream;
static std::set<Asid> tracked_asids;

static std::map<Funid, int> n_calls; //number of calls per function
static int calls_to_monitor_per_fn_entrypoint = 1;
static int enteries_from_callstack_per_fn_entrypoint = 1;
static bool print_addr_as_hex = false;
static uint64_t target_end_count = 0;

// Stores the LLVM visiting information of the called function.
struct LLVMVisitCount {
    uint32_t insn_arit = 0;
    uint32_t insn_tot = 0;
    uint32_t bb = 0; //visitor for basic blocks
    uint32_t insn_load = 0;
    uint32_t insn_store = 0;
    uint32_t insn_intrinsic = 0;
    uint32_t insn_call = 0;
    uint32_t insn_alloc = 0;
    uint32_t modules = 0; //visitor for modules
    uint32_t fn = 0; //visitor for functions
};

// Stores the data byte for a memory address (pc).
struct PCData{
    target_ulong pc;
    uint8_t data;
};

// Stores the information about the called function.
struct CallInfo {
    // Writeset and readset tracking 
    // Log the calls to any given function, together with their writeset, readset, etc
    std::map<Address, PCData> writeset; //memory write set, including memory addresses and data, one byte of data per addr
    std::map<Address, PCData> readset; //memory write set, including memory addresses and data, one byte of data per addr
    std::map<Address, int> block_executions;
    Asid asid;
    uint64_t entrypoint; //the function identifier / entrypoint (the start program counter) / current function
    int writes = 0; //total bytes written to memory
    int reads = 0; //total bytes read from memory
    uint64_t caller;   //the caller addr which is the same as the return address of the stack_entry
    std::vector<Address> callstack; //this is the current callers, same as the stack_entry return_address (tb->pc + tb-size). It contains the block addresses that have led to the call(s) or to the functionstack.
    std::vector<Address> functionstack; //this is the current functions. This also matches IDA Functions (export).
    uint32_t instructions_arith = 0;
    uint32_t instructions_tot = 0;
    uint32_t instructions_mov = 0;
    LLVMVisitCount llvm_count;
    uint64_t rr_instr_count; //to provide a unique identifier for a single record across the whole replay
    // The program counter is the same as the passed pc to mem callbacks, cpu->panda_guest_pc, and get_prog_point. It is the 'call' instruction of the current block from the caller block.
    target_ulong pc;
};

/* Data structures */

// This stores the cached LLVMVisitCount for every basic block.
// So that we avoid re-computing it every time that basic block is encountered.
std::map<target_ulong, LLVMVisitCount> bb_count_cache;
// Tracks if LLVM translation is enabled.
bool llvm_enabled = false;
std::unordered_map<target_ulong, CallInfo> call_infos; 

// Returns the callers asking the callstack_instr plugin.
target_ulong get_current_callers(target_ulong callers[], unsigned int n, CPUState *cpu){
    target_ulong cls_returned = get_callers(callers,n,cpu);
    if(!cls_returned){
//        printf("No cls returned\n");
        return 0;
    }
    return cls_returned;
}

// The visitor which updates an internal LLVMVisitCount on every instruction encountered.
// This is dynamic and verbose as it analyzes the lifted LLVM code (of the called function).
class FnInstVisitor : public llvm::InstVisitor<FnInstVisitor> {
public:

    LLVMVisitCount count;

    void visitBinaryOperator(llvm::BinaryOperator &I){
        count.insn_arit++;
    }

    void visitInstruction(llvm::Instruction &I) {
        count.insn_tot++;
    }

    void visitBasicBlock(llvm::BasicBlock &BB) {
        count.bb++;
    }

    void visitLoadInst(llvm::LoadInst &I) {
        count.insn_load++;
    }

    void visitStoreInst(llvm::StoreInst &I) {
        count.insn_store++;
    }

    void visitIntrinsicInst(llvm::IntrinsicInst &I) {
        count.insn_intrinsic++;
    }

   void visitCallInst(llvm::CallInst &I) {
        count.insn_call++;
    }

    void visitAllocaInst(llvm::AllocaInst &I) {
        count.insn_alloc++;
    }

    void visitModule(llvm::Module &M) {
        count.modules++;
    }

    void visitFunction(llvm::Function &F) {
         count.fn++;
    }
};

// Computes and caches the InstCount for a given basic block.
LLVMVisitCount countAndAddToCache(TranslationBlock *tb){
    FnInstVisitor FIV;
    llvm::Function* bbfn = tb->llvm_function;
    
    if(bbfn){
        FIV.visit(*bbfn);
    } else {
        //printf("No basic block function found! \n");
    }

    target_ulong tb_identifier = tb->pc;
    bb_count_cache[tb_identifier] = FIV.count;
    return FIV.count;
}

std::string uint64_to_hex(const uint64_t uint64_addr){
    char buff[100];
    snprintf(buff, sizeof(buff), "%" PRIx64, uint64_addr);
    std::string buff_str = buff;
    return buff_str;
}

std::string uint64_to_string(uint64_t value) {
    std::ostringstream os;
    os << value;
    return os.str();
}

/* Data access processing */

/* This data structure holds the synthetic description of a given buffer. */
struct bufferinfo {
    target_ulong pc = 0;
    target_ulong base = 0;
    target_ulong len = 0;
    float entropy = -1;
    int printableChars = 0;
    int nulls = 0;

    std::string toString() const {
        std::stringstream ss;
        ss << reinterpret_cast<void*>(base) << "-" << reinterpret_cast<void*>(pc) << "+" << len << ":" << entropy << ";";
        return ss.str();
    }

    nlohmann::json toJSON() const{
        nlohmann::json ret;
        ret["base"] = print_addr_as_hex ? uint64_to_hex(base) : uint64_to_string(base);
        ret["pc"] = print_addr_as_hex ? uint64_to_hex(pc) : uint64_to_string(pc);
        ret["len"] = len;
        ret["entropy"] = entropy;
        ret["printableChars"] = printableChars;
        ret["nulls"] = nulls;
        return ret;
    }
};

/* Computes a vector of BufferInfo from a map<address,data> (readset/writeset) */
std::vector<bufferinfo> toBufferInfos(std::map<target_ulong, PCData>& addrset){
    std::vector<bufferinfo> res;
    bufferinfo temp;
    ShannonEntropyTest ec;

    for (const auto& addr_data : addrset) {
        const auto& addr = addr_data.first;
        const auto& pcdata = addr_data.second;

        if(addr != temp.base + temp.len){
            // start new bufferr.

            // save old buffer (if there's one).
            if(temp.base){
                temp.entropy = ec.get();
                res.push_back(temp);
            }

            // init a new buffer.
            temp = {};
            temp.base = addr;
            temp.pc = pcdata.pc;
            ec.reset();
        }

        // add byte to current buffer.
        temp.len++;
        if(std::isprint(pcdata.data)){
            temp.printableChars++;
        }
        if(pcdata.data == 0){
            temp.nulls++;
        }
        ec.add(pcdata.data);

    }
    // process last buffer (if any - i.e., addrset wasn't empty).
    if(temp.base){
        // save.
        temp.entropy = ec.get();
        res.push_back(temp);
    }

    return res;
}

//We can add more operands here.
static const std::regex ArithMnemonicRegex{R"(add|adc|sub|xor|shr|shl|div|mul|rol|ror|dec)"}; 
static const std::regex MovMnemonicRegex{R"(mov|lea)"};
class ArithOpsCounter {
public:
    uint32_t arith = 0;
    uint32_t total = 0;
    uint32_t movs = 0;

    void fromMnemonic(const char* mnemonic){
        total++;
        bool is_arith = std::regex_search(mnemonic, ArithMnemonicRegex);
        if(is_arith) arith++;
        bool is_mov = std::regex_search(mnemonic, MovMnemonicRegex);
        if(is_mov) movs++;
    }
};

static inline uint32_t tb_idx(CPUState *cpu, TranslationBlock *tb){
    (void) cpu;
    return tb->pc;
}

// Returns the functions' identifiers asking the callstack_instr plugin.
int get_current_functions(target_ulong functions[], unsigned int n, CPUState *cpu){
    int fns_returned = get_functions(functions,n,cpu);
    if(!fns_returned){
//        printf("No fns returned\n");
        return 0;
    }
    return fns_returned;
}

// Returns the current function identifier asking the callstack_instr plugin.
target_ulong get_current_function(CPUState *cpu){
    target_ulong fns[1];
    int fns_returned = get_functions(fns,1,cpu);
    if(!fns_returned){
//        printf("No fns returned\n");
        return 0;
    }
    return fns[0];
}

/* Initializes the call object (with the initial record information) to be further expande and logged*/
void initialize_call_obj(CPUState *cpu, Asid curr_asid, target_ulong entrypoint){
    call_infos[entrypoint].asid = curr_asid;
    call_infos[entrypoint].entrypoint =  entrypoint;
    call_infos[entrypoint].pc = cpu->panda_guest_pc; //same as the passed pc to mem callbacks, get_prog_point, but diferent than tb->pc, since tb->pc is the start of the block, while pc is the trigger
    call_infos[entrypoint].rr_instr_count =  rr_get_guest_instr_count();

    // Get the callstack and functionstack for each call.
    std::vector<target_ulong> callers(enteries_from_callstack_per_fn_entrypoint);
    int callers_n = get_current_callers(callers.data(), static_cast<uint>(callers.size()), cpu);
    callers.resize(callers_n);

    if(callers_n){ //if is populated
        for (const auto& addr : callers){
            //add the addr if it doesn't exist.
             call_infos[entrypoint].callstack.push_back(addr); // without sorting or removing duplicates, this allows searching by the stack in the textprinter output (out-of-the-box)
        }
    }
    call_infos[entrypoint].caller =  callers[0];

    std::vector<target_ulong> functions(enteries_from_callstack_per_fn_entrypoint);
    int functions_n = get_current_functions(functions.data(), static_cast<uint>(functions.size()), cpu);
    functions.resize(functions_n);

    if(functions_n){ //if it is populated
        for (const auto& addr : functions){
            call_infos[entrypoint].functionstack.push_back(addr);
        }
    }
}

// After the execusion of each basic block, log the block(s)' info, right after disassembly.
void after_block_exec_cb(CPUState *cpu, TranslationBlock *tb, unsigned char exitCode) { 

    Asid curr_asid  = panda_current_asid(cpu);

    if (panda_in_kernel(cpu) || !tracked_asids.count(curr_asid)){
            return;
    }
    
    target_ulong current_fn = get_current_function(cpu);

    if (!current_fn) {
       return;
    }

    auto instr_count = rr_get_guest_instr_count();

    if(target_end_count && instr_count > target_end_count){
	panda_replay_end();
    }

    if (!call_infos.count(current_fn)){
        //return; //if we only need the records initiated on call and/or on memory read/write
        initialize_call_obj(cpu, curr_asid, current_fn);
    }

    auto& call = call_infos[current_fn];
    call.block_executions[tb->pc]++; //that is how many times the current block addr got executed, stored in the call's info

    // ######## Disassembly ########
    uint8_t mem[1024] = {};
    int err = panda_virtual_memory_rw(cpu, tb->pc, mem, tb->size, false);
    if(err == -1) {
        printf("Couldn't read TB memory!\n");
    }
    FILE* outbufproc = tmpfile();
    panda_disas(outbufproc, &mem, tb->size); //passing mem or &mem is the same, just the size must be the tb->size. If it is the tb->icount, the instrs will be logged as tb->icount/2.
    ArithOpsCounter aoc;
    std::stringstream buffer;
    buffer <<  (char*) outbufproc->_IO_read_base;
    for (std::string line; std::getline(buffer, line); ) 
    {
        aoc.fromMnemonic(line.c_str()); 
    }
    buffer.flush();
    fclose(outbufproc);
    // ######## Disassembly ########

    auto& counter = aoc;
    call.instructions_arith += counter.arith;
    call.instructions_tot += counter.total;
    call.instructions_mov += counter.movs;

    // ######## llvm_visiting ########
    target_ulong tb_identifier = tb->pc;
    
    // Count the instructions in this basic block (or take from cache).
    LLVMVisitCount llvmVisitCount; 
    
    if (bb_count_cache.count(tb_identifier)) {
        llvmVisitCount = bb_count_cache[tb_identifier];
    } else {
        llvmVisitCount = countAndAddToCache(tb);
    }

    call.llvm_count.insn_arit += llvmVisitCount.insn_arit;
    call.llvm_count.insn_tot += llvmVisitCount.insn_tot;
    call.llvm_count.bb += llvmVisitCount.bb;

    call.llvm_count.insn_load += llvmVisitCount.insn_load;
    call.llvm_count.insn_store += llvmVisitCount.insn_store;
    call.llvm_count.insn_intrinsic += llvmVisitCount.insn_intrinsic;
    call.llvm_count.insn_call += llvmVisitCount.insn_call;
    call.llvm_count.insn_alloc += llvmVisitCount.insn_alloc;
    call.llvm_count.modules += llvmVisitCount.modules;
    call.llvm_count.fn += llvmVisitCount.fn;
    // ######## llvm_visiting ########

    return;
}

/*
This helper helps to clean the stacks, uniqify them, and remove duplicates while keeping the order.
Ex 11,2,3,11,2,3,11,2,3,44 -> 11 2 3 44 (Target)
Ex 11,2,3,111,2,3,11,2,3,44 -> 11 2 3 111 44
*/
struct target_less
{
    template<class It>
    bool operator()(It const &a, It const &b) const { return *a < *b; }
};
struct target_equal
{
    template<class It>
    bool operator()(It const &a, It const &b) const { return *a == *b; }
};
template<class It> It uniquify(It begin, It const end)
{
    std::vector<It> v;
    v.reserve(static_cast<size_t>(std::distance(begin, end)));
    for (It i = begin; i != end; ++i)
    { v.push_back(i); }
    std::sort(v.begin(), v.end(), target_less());
    v.erase(std::unique(v.begin(), v.end(), target_equal()), v.end());
    std::sort(v.begin(), v.end());
    size_t j = 0;
    for (It i = begin; i != end && j != v.size(); ++i)
    {
        if (i == v[j])
        {
            using std::iter_swap; iter_swap(i, begin);
            ++j;
            ++begin;
        }
    }
    return begin;
}


/* on encountring a return instruction, if the CallInfo exists, log it then erase it */
void on_ret_cb(CPUState *cpu, target_ulong entrypoint){

    if (panda_in_kernel(cpu) || !tracked_asids.count(panda_current_asid(cpu))){
        //printf("on_ret return 0\n");
        return;
    }

    if(call_infos.count(entrypoint) == 0){
         return; //the call wasn't logged, as it may have been called more than N times, or simply wasn't caught
    }
    
    auto& call = call_infos[entrypoint];

    std::vector<bufferinfo> writebuffs = toBufferInfos(call.writeset);
    std::vector<bufferinfo> readbuffs = toBufferInfos(call.readset);

    nlohmann::json out;

    std::stringstream line;
    out["asid"] = print_addr_as_hex ? uint64_to_hex(call.asid) : uint64_to_string(call.asid);
    out["pc"] = print_addr_as_hex ? uint64_to_hex(call.pc) : uint64_to_string(call.pc); 
    out["entrypoint"] = print_addr_as_hex ? uint64_to_hex(call.entrypoint) : uint64_to_string(call.entrypoint);
    out["caller"] = print_addr_as_hex ? uint64_to_hex(call.caller) : uint64_to_string(call.caller);

    out["insn_arith"] = call.instructions_arith;
    out["insn_total"] = call.instructions_tot;
    out["insn_movs"] = call.instructions_mov;
    
    out["llvm_insn_arit"] = call.llvm_count.insn_arit;
    out["llvm_insn_tot"] = call.llvm_count.insn_tot;
    out["llvm_bb"] = call.llvm_count.bb;
    out["llvm_insn_load"] = call.llvm_count.insn_load;
    out["llvm_insn_store"] = call.llvm_count.insn_store;
    out["llvm_insn_intrinsic"] = call.llvm_count.insn_intrinsic;
    out["llvm_insn_call"] = call.llvm_count.insn_call;
    out["llvm_insn_alloc"] = call.llvm_count.insn_alloc;
    out["llvm_modules"] = call.llvm_count.modules;
    out["llvm_fn"] = call.llvm_count.fn;

    out["instr_count"] = call.rr_instr_count;

    auto writes = nlohmann::json::array();
    for(const bufferinfo& wrb : writebuffs){
        writes.push_back(wrb.toJSON());
    }

    auto reads = nlohmann::json::array();
    for(const bufferinfo& rdb : readbuffs){
        reads.push_back(rdb.toJSON());
    }
    
    // Reverse the call stack before printing in order to have the most recent element at the right hand side to match textprinter's output to facilitate searching there
    reverse(call.callstack.begin(), call.callstack.end()); 
    auto callstack = nlohmann::json::array();
    for(const auto& addr : call.callstack){
        callstack.push_back(print_addr_as_hex ? uint64_to_hex(addr) : uint64_to_string(addr));
    }

    // Remove duplicates from the functionstack to address the case in which; if the requested limit is greater than the records in the stack, in that case just report a unique stack.
    if (!call.functionstack.empty()) {
        call.functionstack.erase(uniquify(call.functionstack.begin(), call.functionstack.end()), call.functionstack.end());
    }

    // Reverse the func stack before printing in order to have the most recent element at right hand side mainly for readibility.
    reverse(call.functionstack.begin(), call.functionstack.end()); 
    auto functionstack = nlohmann::json::array();
    for(const auto& addr : call.functionstack){
        functionstack.push_back(print_addr_as_hex ? uint64_to_hex(addr) : uint64_to_string(addr));
    }

    out["writes"] = writes;
    out["reads"] = reads;
    out["callstack"] = callstack;
    out["functionstack"] = functionstack;

    int maxexecs = 0; //for the very same call, what was the maximum number of times a block got executed
    target_ulong maxexecs_addr = 0;
    int sumexecs = 0; //for the very same call, what was the sum of all execusions of all blocks
    int distinct = 0; //for the very same call, what was the total number of blocks that got executed
    for(const auto& block_exec : call.block_executions){
        //const auto& pc = block_exec.first;
        const auto& exec = block_exec.second;

        if(exec > maxexecs) {
            maxexecs = exec;
            maxexecs_addr = block_exec.first;
        }

        sumexecs += exec;
        distinct++;
    }

    out["maxexecs"] = maxexecs;
    out["maxexecs_addr"] = print_addr_as_hex ? uint64_to_hex(maxexecs_addr) : uint64_to_string(maxexecs_addr);
    out["sumexecs"] = sumexecs;
    out["distinct_blocks"] = distinct;
    out["nreads"] = call.reads; 
    out["nwrites"] = call.writes;

    outfstream << out.dump() << std::endl;

    call_infos.erase(entrypoint); //careful which one you erase
}

/** When a call instruciton is encountered, create a new CallInfo object. */
void on_call_cb(CPUState *cpu, target_ulong entrypoint){
    
    Asid curr_asid = panda_current_asid(cpu);

    if (panda_in_kernel(cpu) || !tracked_asids.count(curr_asid)){
        return;
    }
    
    // Count the number of calls within this asid
    // and return if we've seen enough calls of this function
    Funid fnid = make_pair(curr_asid, entrypoint);
    n_calls[fnid]++;
    if(n_calls[fnid] > calls_to_monitor_per_fn_entrypoint) {
        //printf("on_call return 1\n");
        return;
    }

    // Create a CallInfo object for this function call.
    initialize_call_obj(cpu, curr_asid, entrypoint);

    // Successive memory callbacks will populate its writeset and readset for the function call.
}

/* Memory access logging */
// On memory write callback
// - checks the cr3 is the right one
// - gets the current_fn to use as identifier for this call
// - gets or creates a CallInfo for this call
// - adds the write to the CallInfo's writeset
void mem_write_callback_cb(CPUState *cpu, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {

    Asid curr_asid = panda_current_asid(cpu);

    if (panda_in_kernel(cpu) || !tracked_asids.count(curr_asid)){
        return;
    }
    
    uint8_t *data = static_cast<uint8_t*>(buf);

    target_ulong current_fn = get_current_function(cpu);

    if (!current_fn) {
        return;
    }

    // If the call info exists, log.
    if(call_infos.count(current_fn)){
        for(target_ulong i=0; i < size; i++){
            call_infos[current_fn].writes++;
            // If this address hasn't been previously written to by the current function, then add it to the writeset.
            if(!call_infos[current_fn].writeset.count(addr + i)){
                call_infos[current_fn].writeset[addr +i].data = data[i];
                call_infos[current_fn].writeset[addr +i].pc = pc;
            }
        }
    } else {
        // We need to create a new CallInfo, then log this write
        initialize_call_obj(cpu, curr_asid, current_fn);
        for(target_ulong i=0; i < size; i++){
            call_infos[current_fn].writes++;
            if(!call_infos[current_fn].writeset.count(addr + i)){
                call_infos[current_fn].writeset[addr + i].data = data[i];
                call_infos[current_fn].writeset[addr +i].pc = pc;
            }
        }
    }

    return;
}


// On memory read callback
// - checks the cr3 is the right one
// - gets the current_fn to use as identifier of this call
// - gets or creates a CallInfo for this call
// - adds the read to the CallInfo's readset
void mem_read_callback_cb(CPUState *cpu, target_ulong pc, target_ulong addr,
                       size_t size, uint8_t *buf) {

    Asid curr_asid = panda_current_asid(cpu);

    if (panda_in_kernel(cpu) || !tracked_asids.count(curr_asid)){
        return;
    }
    
    uint8_t *data = static_cast<uint8_t*>(buf);
    
    target_ulong current_fn = get_current_function(cpu);

    if (!current_fn) {
        return;
    }

    // If the call info exists, log.
    if(call_infos.count(current_fn)){
        for(target_ulong i=0; i < size; i++){
            call_infos[current_fn].reads++;
            // If this address hasn't been previously read from by the current function, then add it to the readset.
            if(!call_infos[current_fn].readset.count(addr + i)){
                call_infos[current_fn].readset[addr +i].data = data[i];
                call_infos[current_fn].readset[addr +i].pc = pc;
            }
        }
    } else {
        // We need to create a new CallInfo, then log this read.
        initialize_call_obj(cpu, curr_asid, current_fn);
        for(target_ulong i=0; i < size; i++){
            call_infos[current_fn].reads++;
                if(!call_infos[current_fn].readset.count(addr + i)) {
                    call_infos[current_fn].readset[addr + i].data = data[i];
                    call_infos[current_fn].readset[addr +i].pc = pc;
                }
        }
    }

    return;
}

/*
For llvm_visiting: Invalidates the cache when translating/re-translating
*/
void after_block_translate_cb (CPUState *cpu, TranslationBlock *tb) {

    Asid curr_asid = panda_current_asid(cpu);

    if (panda_in_kernel(cpu) || !tracked_asids.count(curr_asid)){
        return;
    }

    //##### llvm_visiting #####
    bb_count_cache.erase(tb->pc);
    //##### llvm_visiting #####
     
  return;
}

/* For plugin initialization: to parse given asids to track*/
std::set<target_ulong> parse_addr_list(const char* addrs){
    std::set<target_ulong> res;
    if(!addrs) return res;

    char* arrt = strdup(addrs);

    char* pch = strtok(arrt, "_");
    while (pch != NULL){
        res.insert(static_cast<target_ulong>(std::stoul(pch, nullptr, 0)));
        pch = strtok(NULL, "_");
    }

    free(arrt);
    return res;
}

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;

    panda_cb pcb;

    printf("Enabling LLVM\n");
    panda_enable_llvm();
    panda_enable_llvm_helpers();

    pcb.after_block_translate = after_block_translate_cb; //1
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec_cb; //2
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.virt_mem_after_write = mem_write_callback_cb; //3
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    pcb.virt_mem_after_read = mem_read_callback_cb; //4
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);


    PPP_REG_CB("callstack_instr", on_call, on_call_cb); //whenver a call instruction is encountered
    PPP_REG_CB("callstack_instr", on_ret, on_ret_cb); //whenever a ret instr is encountered

    panda_disable_tb_chaining();
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("func_stats");
    if (args != NULL) {
        const char* asids = panda_parse_string(args, "asids", "list of address space identifiers to track (separated by '_')");
        tracked_asids = parse_addr_list(asids);
        target_end_count = panda_parse_uint64_opt(args, "endat", 0, "instruction count when to end the replay");
        calls_to_monitor_per_fn_entrypoint = static_cast<int>(panda_parse_uint32_opt(args, "call_limit", 32, "how many calls to monitor per entrypoint (or per called function)"));
        enteries_from_callstack_per_fn_entrypoint = static_cast<int>(panda_parse_uint32_opt(args, "stack_limit", 2, "how many enteries to retreive from the callstack"));
        print_addr_as_hex = panda_parse_bool_opt(args, "hex", "print addresses as hex");
    }

    for(const target_ulong asid: tracked_asids){
        printf("tracking asid " TARGET_FMT_ld  " \n", asid);
    }

    outfstream.open("func_stats");
    if(outfstream.fail()){
        return false;
    }

    return true;
}

/* 
    Logs to the standard out; the calls that haven't returned. Note that, these calls haven't been logged.
 */
void printstats(){
    std::cerr << "Missed calls: " << std::endl;
    for(auto const& call_ci : call_infos){
        auto& call = call_ci.second;
        std::cerr 
        << "MISSED_RETURN_OF_FN " <<  (print_addr_as_hex ? uint64_to_hex(call.entrypoint) : uint64_to_string(call.entrypoint))  
        //<< "AT_PC " <<  (print_addr_as_hex ? uint64_to_hex(call.pc) : uint64_to_string(call.pc)) 
        << std::endl;
    }
}

void uninit_plugin(void *self) {
    (void) self;
    outfstream.flush();
    outfstream.close();
    printstats();
}

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

#include "tubtf.h"
#include "panda_memlog.h"

using namespace llvm;

#define MAX_BITSET 2048
#define FMT64 "%" PRIx64

std::string TubtfEITypeStr[TUBTFE_LLVM_EXCEPTION+1] = {
    "TUBTFE_USE",
    "TUBTFE_DEF",
    "TUBTFE_TJMP",
    "TUBTFE_TTEST",
    "TUBTFE_TCMP",
    "TUBTFE_TLDA",
    "TUBTFE_TLDV",
    "TUBTFE_TSTA",
    "TUBTFE_TSTV",
    "TUBTFE_TFNA_VAL",
    "TUBTFE_TFNA_PTR",
    "TUBTFE_TFNA_STR",
    "TUBTFE_TFNA_ECX",
    "TUBTFE_TFNA_EDX",
    "TUBTFE_TVE_JMP",
    "TUBTFE_TVE_TEST_T0",
    "TUBTFE_TVE_TEST_T1",
    "TUBTFE_TVE_CMP_T0",
    "TUBTFE_TVE_CMP_T1",
    "TUBTFE_TVE_LDA",
    "TUBTFE_TVE_LDV",
    "TUBTFE_TVE_STA",
    "TUBTFE_TVE_STV",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "TUBTFE_LLVM_FN",
    "TUBTFE_LLVM_DV_LOAD",
    "TUBTFE_LLVM_DV_STORE",
    "TUBTFE_LLVM_DV_BRANCH",
    "TUBTFE_LLVM_DV_SELECT",
    "TUBTFE_LLVM_DV_SWITCH",
    "TUBTFE_LLVM_EXCEPTION",
};

#ifdef __APPLE__
#define O_LARGEFILE 0
#endif

enum SliceVarType {
    LLVM,
    MEM,
    HOST,
    REG,
    SPEC,
    FRET
};
uint64_t ret_ctr = 0;

typedef std::pair<SliceVarType,uint64_t> SliceVar;

std::string SliceVarStr(const SliceVar &s) {
    char output[128] = {};

    switch (s.first) {
        case LLVM:
            sprintf(output, "LLVM_%x", s.second);
            break;
        case MEM:
            sprintf(output, "MEM_%x", s.second);
            break;
        case HOST:
            sprintf(output, "HOST_%x", s.second);
            break;
        case REG:
            sprintf(output, "REG_%x", s.second);
            break;
        case SPEC:
            sprintf(output, "SPEC_%x", s.second);
            break;
        case FRET:
            sprintf(output, "RET_%x", s.second);
            break;
        default:
            assert (false && "No such SliceVarType");
    }

    return output;
}

SliceVar VarFromStr(const char *str) {
    SliceVarType typ;
    uint64_t addr = 0;
    char *addrstr;

    char *work = strdup(str);
    char *c = work;
    while (*c) {
        if (*c == '_') {
            *c = '\0';
            addrstr = c+1;
        }
        c++;
    }
    sscanf(addrstr, "%x", &addr);

    if (strncmp(str, "LLVM", 4) == 0) {
        typ = LLVM;
    }
    else if (strncmp(str, "MEM", 3) == 0) {
        typ = MEM;
    }
    else if (strncmp(str, "REG", 3) == 0) {
        typ = REG;
    }
    else if (strncmp(str, "HOST", 4) == 0) {
        typ = HOST;
    }
    else if (strncmp(str, "SPEC", 4) == 0) {
        typ = SPEC;
    }
    else if (strncmp(str, "RET", 3) == 0) {
        typ = FRET;
    }
    else {
        assert (false && "Bad SliceVarType");
    }

    free(work);

    return std::make_pair(typ, addr);
}

struct __attribute__((packed)) TUBTEntry {
    uint64_t asid;
    uint64_t pc;
    uint64_t type;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
};

bool debug = false;
bool include_branches = false;

static void extract_addrentry(uint64_t entry, AddrType &typ, AddrFlag &flag, int &off) {
    typ = (AddrType) (entry & 0xff);
    flag = (AddrFlag) ((entry >> 8) & 0xff);
    off = entry >> 16;
}

const char * addrflag_str(AddrFlag a) {
    switch (a) {
        case IRRELEVANT: return "IRRELEVANT";
        case EXCEPTION: return "EXCEPTION";
        case READLOG: return "READLOG";
        case FUNCARG: return "FUNCARG";
        case 0: return "0";
        default: return "????";
    }
}

const char * addrtype_str(AddrType t) {
    switch(t) {
        case HADDR: return "HADDR";
        case MADDR: return "MADDR";
        case IADDR: return "IADDR";
        case PADDR: return "PADDR";
        case LADDR: return "LADDR";
        case GREG: return "GREG";
        case GSPEC: return "GSPEC";
        case UNK: return "UNK";
        case CONST: return "CONST";
        case RET: return "RET";
        default: return "????";
    }
}

void dump_tubt(TUBTEntry *row) {
    switch (row->type) {
        case TUBTFE_LLVM_DV_LOAD:
        case TUBTFE_LLVM_DV_STORE:
        {
            AddrType typ;
            AddrFlag flag;
            int off;
            extract_addrentry(row->arg1, typ, flag, off);
            printf(FMT64 " " FMT64 " %s AddrType=%s AddrFlag=%s off=%d " FMT64 " " FMT64 " " FMT64 "\n",
                    row->asid, row->pc, TubtfEITypeStr[row->type].c_str(),
                    addrtype_str(typ), addrflag_str(flag), off,
                    row->arg2, row->arg3, row->arg4);
            break;
        }
        default:
            printf(FMT64 " " FMT64 " %s " FMT64 " " FMT64 " " FMT64 " " FMT64 "\n", row->asid,
                    row->pc, TubtfEITypeStr[row->type].c_str(),
                    row->arg1, row->arg2, row->arg3, row->arg4);
            break;
    }
}

struct trace_entry {
    uint32_t index; // index of instruction in the original function
    Function *func;
    Instruction *insn;
    TUBTEntry *dyn;
    TUBTEntry *dyn2; // Just for memcpy because it's a special snowflake
};

static SliceVar get_value_name(Value *v) {
    return std::make_pair(LLVM, (uint64_t)v);
}

static void insertValue(std::set<SliceVar> &s, Value *v) {
    if (!isa<Constant>(v)) s.insert(get_value_name(v));
}

int getLoadSize(LoadInst *l) {
    Value *pt = l->getPointerOperand();
    Type *t = pt->getType()->getPointerElementType();
    return t->getPrimitiveSizeInBits() / 8;
}

int getStoreSize(StoreInst *s) {
    Value *v = s->getValueOperand();
    Type *t = v->getType();
    return t->getPrimitiveSizeInBits() / 8;
}

// Adds the appropriate values to a use/def set given an
// AddrEntry. NOTE: don't use this on __ld / __st, as the
// MADDR type means something different in that context.
// arg2 is the TUBT arg2 column
void insertAddr(std::set<SliceVar> &s, AddrType typ, uint64_t arg2, int sz) {
    switch (typ) {
        case GREG:
            s.insert(std::make_pair(REG, arg2));
            break;
        case MADDR:
            for (int off = 0; off < sz; off++)
                s.insert(std::make_pair(HOST, arg2+off));
            break;
        case GSPEC:
            s.insert(std::make_pair(SPEC,arg2));
            break;
        default:
            printf("Warning: unhandled address entry type %d\n", typ);
            break;
    }
}

// Handlers for individual instruction types

static void handleStore(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    StoreInst *s = cast<StoreInst>(t.insn);
    AddrType typ;
    AddrFlag flag;
    int off;
    extract_addrentry(t.dyn->arg1, typ, flag, off);

    if (!s->isVolatile() && flag != IRRELEVANT) {
        insertAddr(defs, typ, t.dyn->arg2, getStoreSize(s));
        Value *v = s->getValueOperand();
        insertValue(uses, v);
        Value *p = s->getPointerOperand();
        insertValue(uses, p);
    }
    return;
}

static void handleLoad(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    LoadInst *l = cast<LoadInst>(t.insn);
    AddrType typ;
    AddrFlag flag;
    int off;
    extract_addrentry(t.dyn->arg1, typ, flag, off);

    if (flag != IRRELEVANT) {
        insertAddr(uses, typ, t.dyn->arg2, getLoadSize(l));
    }
    Value *p = l->getPointerOperand();
    insertValue(uses, p);
    // Even IRRELEVANT loads can define things
    insertValue(defs, t.insn);
    return;
}

static void handleDefault(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    for (User::op_iterator i = t.insn->op_begin(), e = t.insn->op_end(); i != e; ++i) {
        Value *v = *i;
        if (!isa<BasicBlock>(v)) { // So that br doesn't end up with block refs
            insertValue(uses, *i);
        }
    }
    insertValue(defs, t.insn);
    return;
}

static void handleCall(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    CallInst *c =  cast<CallInst>(t.insn);
    Function *subf = c->getCalledFunction();
    StringRef func_name = subf->getName();
    if (func_name.startswith("__ld")) {
        char sz_c = func_name[4];
        int size = -1;
        switch(sz_c) {
            case 'q': size = 8; break;
            case 'l': size = 4; break;
            case 'w': size = 2; break;
            case 'b': size = 1; break;
            default: assert(false && "Invalid size in call to load");
        }
        for (int off = 0; off < size; off++) {
            uses.insert(std::make_pair(MEM, t.dyn->arg2 + off));
        }
        Value *load_addr = c->getArgOperand(0);
        insertValue(uses, load_addr);
        insertValue(defs, t.insn);
    }
    else if (func_name.startswith("__st")) {
        char sz_c = func_name[4];
        int size = -1;
        switch(sz_c) {
            case 'q': size = 8; break;
            case 'l': size = 4; break;
            case 'w': size = 2; break;
            case 'b': size = 1; break;
            default: assert(false && "Invalid size in call to store");
        }
        for (int off = 0; off < size; off++) {
            defs.insert(std::make_pair(MEM, t.dyn->arg2 + off));
        }
        Value *store_addr = c->getArgOperand(0);
        Value *store_val  = c->getArgOperand(1);
        insertValue(uses, store_addr);
        insertValue(uses, store_val);
    }
    else if (func_name.startswith("llvm.memcpy")) {
        AddrType typ;
        AddrFlag flag;
        int off;

        // Get memcpy size
        int bytes = 0;
        Value *bytes_ir = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Load first
        extract_addrentry(t.dyn->arg1, typ, flag, off);
        if (flag != IRRELEVANT)
            insertAddr(uses, typ, t.dyn->arg2, bytes);

        // Now store
        extract_addrentry(t.dyn2->arg1, typ, flag, off);
        if (flag != IRRELEVANT)
            insertAddr(defs, typ, t.dyn2->arg2, bytes);

        // Src/Dst pointers
        insertValue(uses, c->getArgOperand(0));
        insertValue(uses, c->getArgOperand(1));
        
    }
    else if (func_name.startswith("llvm.memset")) {
        AddrType typ;
        AddrFlag flag;
        int off;

        int bytes = 0;
        Value *bytes_ir  = const_cast<Value*>(c->getArgOperand(2));
        ConstantInt* CI = dyn_cast<ConstantInt>(bytes_ir);
        if (CI && CI->getBitWidth() <= 64) {
            bytes = CI->getSExtValue();
        }

        // Now store
        extract_addrentry(t.dyn->arg1, typ, flag, off);
        if (flag != IRRELEVANT)
            insertAddr(defs, typ, t.dyn->arg2, bytes);

        // Dst pointer
        insertValue(uses, c->getArgOperand(0));

        // Value (if not constant)
        insertValue(uses, c->getArgOperand(1));
    }
    else if (func_name.equals("helper_inb") ||
             func_name.equals("helper_inw") ||
             func_name.equals("helper_inl")) {
        insertValue(uses, c->getArgOperand(0));
        insertValue(defs, c);
    }
    else if (func_name.equals("helper_outb") ||
             func_name.equals("helper_outw") ||
             func_name.equals("helper_outl")) {
        // We don't have any model of port I/O, so
        // we just ignore this one
    }
    else if (func_name.equals("log_dynval")) {
        // ignore
    }
    else {
        // call to some helper
        if (!c->getType()->isVoidTy()) {
            insertValue(defs, c);
        }
        // Uses the return value of that function.
        // Note that it does *not* use the arguments -- these will
        // get included automatically if they're needed to compute
        // the return value.
        uses.insert(std::make_pair(FRET, ret_ctr));
    }
    return;
}

static void handleRet(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {

    ReturnInst *r = cast<ReturnInst>(t.insn);
    Value *v = r->getReturnValue();
    if (v != NULL) insertValue(uses, v);

    defs.insert(std::make_pair(FRET, ret_ctr++));
}

static void handlePHI(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    // arg1 is the fake dynamic value we derived during trace alignment
    PHINode *p = cast<PHINode>(t.insn);
    Value *v = p->getIncomingValue(t.dyn->arg1);
    insertValue(uses, v);
    insertValue(defs, t.insn);
}

static void handleSelect(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {

    SelectInst *s = cast<SelectInst>(t.insn);
    Value *v;
    // These are negated in the dynamic log from what you'd expect
    if (t.dyn->arg1 == 1)
        v = s->getFalseValue();
    else
        v = s->getTrueValue();

    insertValue(uses, v);
    insertValue(uses, s->getCondition());
    insertValue(defs, t.insn);
}

// I don't *think* we can use LLVM's InstructionVisitor here because actually
// want to operate on a trace element, not an Instruction (and hence we need
// the accompanying dynamic info).
void get_uses_and_defs(trace_entry &t,
        std::set<SliceVar> &uses,
        std::set<SliceVar> &defs) {
    switch (t.insn->getOpcode()) {
        case Instruction::Store:
            handleStore(t, uses, defs);
            return;
        case Instruction::Load:
            handleLoad(t, uses, defs);
            return;
        case Instruction::Call:
            handleCall(t, uses, defs);
            return;
        case Instruction::Ret:
            handleRet(t, uses, defs);
            return;
        case Instruction::PHI:
            handlePHI(t, uses, defs);
            return;
        case Instruction::Select:
            handleSelect(t, uses, defs);
            return;
        case Instruction::Unreachable: // how do we even get these??
            return;
        case Instruction::Br:
        case Instruction::Switch:
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
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::Trunc:
        case Instruction::BitCast:
        case Instruction::GetElementPtr: // possible loss of precision
        case Instruction::ExtractValue:
        case Instruction::InsertValue:
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr:
        case Instruction::ICmp:
        case Instruction::FCmp:
        case Instruction::Alloca:
            handleDefault(t, uses, defs);
            return;
        default:
            printf("Note: no model for %s, assuming uses={operands} defs={lhs}\n", t.insn->getOpcodeName());
            // Try "default" operand handling
            // defs = LHS, right = operands

            handleDefault(t, uses, defs);
            return;
    }
    return;
}

std::map<std::pair<Function*,int>,std::bitset<MAX_BITSET>> marked;

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

void mark(trace_entry &t) {
    int bb_num = t.index >> 16;
    int insn_index = t.index & 0xffff;
    assert (insn_index < MAX_BITSET);
    marked[std::make_pair(t.func,bb_num)][insn_index] = true;
    if (debug)
        printf("Marking %s, block %d, instruction %d.\n", t.func->getName().str().c_str(), bb_num, insn_index);
}

void print_insn(Instruction *insn) {
    std::string s;
    raw_string_ostream ss(s);
    insn->print(ss);
    ss.flush();
    printf("%s\n", ss.str().c_str());
    return;
}

bool is_ignored(Function *f) {
    StringRef func_name = f->getName();
    if (func_name.startswith("__ld") ||
        func_name.startswith("__st") ||
        func_name.startswith("llvm.memcpy") || 
        func_name.startswith("llvm.memset") ||
        func_name.equals("helper_inb") ||
        func_name.equals("helper_inw") ||
        func_name.equals("helper_inl") ||
        func_name.equals("helper_outb") ||
        func_name.equals("helper_outw") ||
        func_name.equals("helper_outl") ||
        func_name.equals("log_dynval"))
        return true;
    else
        return false;
}

void print_set(std::set<SliceVar> &s) {
    printf("{");
    for (const SliceVar &w : s) printf(" %s", SliceVarStr(w).c_str());
    printf(" }\n");
}

// Core slicing algorithm. If the current instruction
// defines something we currently care about, then kill
// the defs and add in the uses.
// Note that this *modifies* the working set 'work' and
// updates the global map of LLVM functions => bitsets
void slice_trace(std::vector<trace_entry> &trace,
        std::set<SliceVar> &work) {
    Function *entry_func = trace[0].func;

    // Keeps track of argument->value binding when we descend into
    // functions
    std::stack<std::map<SliceVar,SliceVar>> argmap_stack;

    for(std::vector<trace_entry>::reverse_iterator it = trace.rbegin();
            it != trace.rend(); it++) {

        // Skip helper functions for now
        // if (it->func != entry_func) continue;

        if (debug) printf(">> %s\n", it->insn->getOpcodeName());
        if (debug) print_insn(it->insn);

        std::set<SliceVar> uses, defs;
        get_uses_and_defs(*it, uses, defs);

        if (debug) printf("DEBUG: %lu defs, %lu uses\n", defs.size(), uses.size());
        if (debug) printf("DEFS: ");
        if (debug) print_set(defs);
        if (debug) printf("USES: ");
        if (debug) print_set(uses);

        if (it->func != entry_func) {
            // If we're not at top level (i.e. we're in a helper function)
            // we need to map the uses through the current argument map. We
            // don't need to do this with the defs because you can't define
            // a function argument inside the function.
            for (auto it = uses.begin(); it != uses.end(); ) {
                std::map<SliceVar,SliceVar> &argmap = argmap_stack.top();
                auto arg_it = argmap.find(*it);
                if (arg_it != argmap.end()) {
                    uses.erase(it++);
                    uses.insert(arg_it->second);
                }
                else {
                    ++it;
                }
            }

            if (debug) printf("USES (remapped): ");
            if (debug) print_set(uses);
        }
        
        bool has_overlap = false;
        for (auto &s : defs) {
            if (work.find(s) != work.end()) {
                has_overlap = true;
                break;
            }
        }

        if (has_overlap) {
            if (debug) printf("Current instruction defines something in the working set\n");

            // Mark the instruction
            mark(*it);

            // Update the working set
            for (auto &d : defs) work.erase(d);
            work.insert(uses.begin(), uses.end());

        }
        else if (it->insn->isTerminator() && !isa<ReturnInst>(it->insn) && include_branches) {
            // Special case: branch/switch
            if (debug) printf("Current instruction is a branch, adding it.\n");
            mark(*it);
            work.insert(uses.begin(), uses.end());
        }

        // Special handling for function calls. We need to bind arguments to values
        if (CallInst *c = dyn_cast<CallInst>(it->insn)) {
            std::map<SliceVar,SliceVar> argmap;
            Function *subf = c->getCalledFunction();

            if (!is_ignored(subf)) {
                // Iterate over pairs of arguments & values
                Function::arg_iterator argIter;
                int p;
                for (argIter = subf->arg_begin(), p = 0;
                     argIter != subf->arg_end() && p < c->getNumArgOperands();
                     argIter++, p++) {
                    argmap[get_value_name(&*argIter)] = get_value_name(c->getArgOperand(p));
                    if (debug) printf("ArgMap %s => %s\n", SliceVarStr(get_value_name(&*argIter)).c_str(), SliceVarStr(get_value_name(c->getArgOperand(p))).c_str());
                }
                argmap_stack.push(argmap);
            }
        }
        else if (&*(it->func->getEntryBlock().begin()) == &*(it->insn)) {
            // If we just processed the first instruction in the function,
            // we must be about to exit the function, so pop the stack
            if(!argmap_stack.empty()) argmap_stack.pop();
        }

        if (debug) printf("Working set: ");
        if (debug) print_set(work);
    }

    // At the end we want to get rid of the argument to the basic block,
    // since it's just env.
    work.erase(get_value_name(&*entry_func->arg_begin()));
}

// Find the index of a block in a function
int getBlockIndex(Function *f, BasicBlock *b) {
    int i = 0;
    for (Function::iterator it = f->begin(), ed = f->end(); it != ed; ++it) {
        if (&*it == b) return i;
        i++;
    }
    return -1;
}

// Ugly to use a global here. But at an exception we have to return out of
// an unknown number of levels of recursion.
bool in_exception = false;

TUBTEntry * process_func(Function *f, TUBTEntry *dynvals, std::vector<trace_entry> &serialized) {
    TUBTEntry *cursor = dynvals;
    BasicBlock &entry = f->getEntryBlock();
    BasicBlock *block = &entry;
    bool have_successor = true;
    while (have_successor) {
        have_successor = false;
        
        int bb_index = getBlockIndex(f, block);
        int insn_index = 0;
        for (BasicBlock::iterator i = block->begin(), e = block->end(); i != e; ++i) {
            trace_entry t = {};
            t.index = insn_index | (bb_index << 16);
            insn_index++;

            // Bail out if we're we're in an exception
            if (in_exception) return cursor;

            // Peek at the next thing in the log. If it's an exception, no point
            // processing anything further, since we know there can be no dynamic
            // values before the exception.
            if (cursor->type == TUBTFE_LLVM_EXCEPTION) {
                if (debug) printf("Found exception, will not finish this function.\n");
                in_exception = true;
                cursor++;
                return cursor;
            }

            if (debug) print_insn(&*i);

            switch (i->getOpcode()) {
                case Instruction::Load: {
                    assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                    if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized.push_back(t);
                    cursor++;
                    break;
                }
                case Instruction::Store: {
                    StoreInst *s = cast<StoreInst>(&*i);
                    if (!s->isVolatile()) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    break;
                }
                case Instruction::Br: {
                    assert(cursor->type == TUBTFE_LLVM_DV_BRANCH);
                    BranchInst *b = cast<BranchInst>(&*i);
                    block = b->getSuccessor(cursor->arg1);
                    if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized.push_back(t);
                    cursor++;
                    have_successor = true;
                    break;
                }
                case Instruction::Switch: {
                    assert(cursor->type == TUBTFE_LLVM_DV_SWITCH);
                    SwitchInst *s = cast<SwitchInst>(&*i);
                    unsigned width = s->getCondition()->getType()->getPrimitiveSizeInBits();
                    IntegerType *intType = IntegerType::get(getGlobalContext(), width);
                    ConstantInt *caseVal = ConstantInt::get(intType, cursor->arg1);
                    SwitchInst::CaseIt caseIndex = s->findCaseValue(caseVal);
                    block = s->getSuccessor(caseIndex.getSuccessorIndex());
                    if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized.push_back(t);
                    cursor++;
                    have_successor = true;
                    break;
                }
                case Instruction::PHI: {
                    // We don't actually have a dynamic log entry here, but for
                    // convenience we do want to know which basic block we just
                    // came from. So we peek at the previous non-PHI thing in
                    // our trace, which should be the predecessor basic block
                    // to this PHI
                    PHINode *p = cast<PHINode>(&*i);
                    TUBTEntry *new_dyn = new TUBTEntry;
                    new_dyn->arg1 = -1; // sentinel
                    // Find the last non-PHI instruction
                    for (auto sit = serialized.rbegin(); sit != serialized.rend(); sit++) {
                        if (sit->insn->getOpcode() != Instruction::PHI) {
                            new_dyn->arg1 = p->getBasicBlockIndex(sit->insn->getParent());
                            break;
                        }
                    }
                    assert(new_dyn->arg1 != (uint64_t) -1);
                    t.func = f; t.insn = i; t.dyn = new_dyn;
                    serialized.push_back(t);
                    break;
                }
                case Instruction::Select: {
                    assert(cursor->type == TUBTFE_LLVM_DV_SELECT);
                    if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized.push_back(t);
                    cursor++;
                    break;
                }
                case Instruction::Call: {
                    CallInst *c =  cast<CallInst>(&*i);
                    Function *subf = c->getCalledFunction();
                    assert(subf != NULL);
                    StringRef func_name = subf->getName();
                    if (func_name.startswith("__ld")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("__st")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memcpy")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        cursor++;
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.dyn2 = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memset")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.equals("helper_inb") ||
                             func_name.equals("helper_inw") ||
                             func_name.equals("helper_inl")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.equals("helper_outb") ||
                             func_name.equals("helper_outw") ||
                             func_name.equals("helper_outl")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized.push_back(t);
                        cursor++;
                    }
                    else if (func_name.equals("log_dynval") ||
                             subf->isDeclaration() ||
                             subf->isIntrinsic()) {
                        // ignore
                    }
                    else {
                        // descend
                        cursor = process_func(subf, cursor, serialized);
                        // Put the call in *after* the instructions so we
                        // can decide if we need the return value
                        t.func = f; t.insn = i; t.dyn = NULL;
                        serialized.push_back(t);
                    }
                    break;
                }
                default:
                    t.func = f; t.insn = i; t.dyn = NULL;
                    serialized.push_back(t);
                    break;
            }
        }
    }
    return cursor;
}

static inline void update_progress(uint64_t cur, uint64_t total) {
    double pct = cur / (double)total;
    const int columns = 80;
    printf("[");
    int pos = columns*pct;
    for (int i = 0; i < columns; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %02d%%\r", (int)(pct*100));
    fflush(stdout);
}

void usage(char *prog) {
   fprintf(stderr, "Usage: %s [OPTIONS] <llvm_mod> <dynlog> <criterion> [<criterion> ...]\n",
           prog);
   fprintf(stderr, "Options:\n"
           "  -b                : include branch conditions in slice\n"
           "  -d                : enable debug output\n"
           "  -v                : show progress meter\n"
           "  -a                : just align, don't slice\n"
           "  -w                : print working set after each block\n"
           "  -n NUM -p PC      : skip ahead to TB NUM-PC\n"
           "  -o OUTPUT         : save results to OUTPUT\n"
           "  <llvm_mod>        : the LLVM bitcode module\n"
           "  <dynlog>          : the TUBT log file\n"
           "  <criterion> ...   : the slicing criteria, i.e., what to slice on\n"
           "                      Use REG_[N] for registers, MEM_[PADDR] for memory\n"
          );
}

int main(int argc, char **argv) {
    // mmap the dynamic log

    int opt;
    unsigned long num, pc;
    bool show_progress = false;
    bool have_num = false, have_pc = false;
    bool print_work = false;
    bool align_only = false;
    const char *output = NULL;
    while ((opt = getopt(argc, argv, "vawbdn:p:o:")) != -1) {
        switch (opt) {
        case 'n':
            num = strtoul(optarg, NULL, 10);
            have_num = true;
            break;
        case 'p':
            pc = strtoul(optarg, NULL, 16);
            have_pc = true;
            break;
        case 'd':
            debug = true;
            break;
        case 'b':
            include_branches = true;
            break;
        case 'w':
            print_work = true;
            break;
        case 'a':
            align_only = true;
            break;
        case 'o':
            output = optarg;
            break;
        case 'v':
            show_progress = true;
            break;
        default: /* '?' */
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (have_num != have_pc) {
        fprintf(stderr, "ERROR: cannot specify -p without -n (and vice versa).\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (optind + 1 >= argc) {
        fprintf(stderr, "ERROR: both <llvm_mod> and <dynlog> are required.\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    if (optind + 2 >= argc) {
        fprintf(stderr, "WARNING: You did not specify any slicing criteria. This is probably not what you want.\n");
        fprintf(stderr, "Continuing anyway.\n");
    }

    if (output == NULL) {
        output = "slice_report.bin";
        fprintf(stderr, "Note: no output file provided. Will save results to '%s'\n", output);
    }

    char *llvm_mod_fname = argv[optind];
    char *tubt_log_fname = argv[optind+1];

    // Add the slicing criteria
    std::set<SliceVar> work;
    for (int i = optind + 2; i < argc; i++) {
        work.insert(VarFromStr(argv[i]));
    }

    struct stat st;
    if (stat(tubt_log_fname, &st) != 0) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    uint64_t num_rows = (st.st_size - 20) / sizeof(TUBTEntry);
    int fd = open(tubt_log_fname, O_RDWR|O_LARGEFILE);
    uint8_t *mapping = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    TUBTEntry *rows = (TUBTEntry *)(mapping + 20);
    TUBTEntry *endp = rows + num_rows;

    LLVMContext &ctx = getGlobalContext();

    // Load the bitcode...
    SMDiagnostic err;

    Module *mod = ParseIRFile(llvm_mod_fname, err, ctx);

    TUBTEntry *cursor = rows;
    if (have_pc) {
        while (!(cursor->type == TUBTFE_LLVM_FN && cursor->pc == pc && cursor->arg1 == num)) cursor++;
    }

    uint64_t rows_processed = 0;

    printf("Slicing trace...\n");
    while (cursor != endp) {
        assert (cursor->type == TUBTFE_LLVM_FN);
        char namebuf[128];
        sprintf(namebuf, "tcg-llvm-tb-%llu-%llx", cursor->arg1, cursor->pc);
        if (debug) printf("********** %s **********\n", namebuf);
        Function *f = mod->getFunction(namebuf);
        assert(f != NULL);

        TUBTEntry *dbgcurs = cursor + 1;
        if (debug) while (dbgcurs->type != TUBTFE_LLVM_FN) dump_tubt(dbgcurs++);

        cursor++; // Don't include the function entry

        // Get the aligned trace of this block
        in_exception = false; // reset this in case the last function ended with an exception
        std::vector<trace_entry> aligned_block;
        cursor = process_func(f, cursor, aligned_block);

        // And slice it
        if (!align_only) slice_trace(aligned_block, work);

        if (print_work) printf("Working set: ");
        if (print_work) print_set(work);

        rows_processed = cursor - rows;
        if (show_progress) update_progress(rows_processed, num_rows);

        if (work.empty() && !align_only) {
            printf("\n");
            printf("Note: working set is empty, will stop slicing.\n");
            break;
        }
    }

    printf("\n");

    uint64_t insns_marked = 0;
    for (auto &kvp : marked) insns_marked += kvp.second.count();
    printf("Done slicing. Marked %lu blocks, %llu instructions.\n", marked.size(), insns_marked);

    // Write slice report
    FILE *outf = fopen(output, "wb");
    for (auto &kvp : marked) {
        uint32_t name_size = 0;
        uint32_t index = kvp.first.second;
        uint8_t bytes[MAX_BITSET/8] = {};

        StringRef name = kvp.first.first->getName();
        name_size = name.size();
        bits2bytes(kvp.second, bytes);

        fwrite(&name_size, sizeof(uint32_t), 1, outf);
        fwrite(name.str().c_str(), name_size, 1, outf);
        fwrite(&index, sizeof(uint32_t), 1, outf);
        fwrite(bytes, MAX_BITSET / 8, 1, outf);
    }
    fclose(outf);
    printf("Wrote slicing results to %s\n", output);

    return 0;
}

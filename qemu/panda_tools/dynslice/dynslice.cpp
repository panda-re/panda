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
#define INCLUDE_BRANCHES 1
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

void dump_tubt(TUBTEntry *row) {
    printf(FMT64 " " FMT64 " %s " FMT64 " " FMT64 " " FMT64 " " FMT64 "\n", row->asid, row->pc, TubtfEITypeStr[row->type].c_str(), row->arg1, row->arg2, row->arg3, row->arg4);
}

struct trace_entry {
    uint32_t index; // index of instruction in the original function
    Function *func;
    Instruction *insn;
    TUBTEntry *dyn;
    TUBTEntry *dyn2; // Just for memcpy because it's a special snowflake
};

static void extract_addrentry(uint64_t entry, int &typ, int &flag, int &off) {
    typ = entry & 0xff;
    flag = (entry >> 8) & 0xff;
    off = entry >> 16;
}

static std::string get_value_name(Value *v) {
    if (v->hasName()) {
        return v->getName().str();
    }
    else {
        // Unnamed values just use the pointer
        char name[128] = {};
        sprintf(name, "LV_%llx", (uint64_t)v);
        return name;
    }
}

// Handlers for individual instruction types

static void handleStore(trace_entry &t,
        std::set<std::string> &uses,
        std::set<std::string> &defs) {
    StoreInst *s = cast<StoreInst>(t.insn);
    int typ, flag, off;
    extract_addrentry(t.dyn->arg1, typ, flag, off);

    if (!s->isVolatile() && flag != IRRELEVANT) {
        switch (typ) {
            case GREG:
                defs.insert("REG_" + std::to_string(t.dyn->arg2));
                break;
            case MADDR:
                //printf("Warning: what is MADDR? Val=%llx\n", t.dyn->arg2);
                defs.insert("HOST_" + std::to_string(t.dyn->arg2));
                break;
            case GSPEC:
                defs.insert("SPEC_" + std::to_string(t.dyn->arg2));
                break;
            default:
                printf("Warning: unhandled address entry type %d\n", typ);
                break;
        }
        Value *v = s->getValueOperand();
        if (!isa<Constant>(v)) {
            uses.insert(get_value_name(v));
        }
    }
    return;
}

static void handleLoad(trace_entry &t,
        std::set<std::string> &uses,
        std::set<std::string> &defs) {
    LoadInst *s = cast<LoadInst>(t.insn);
    int typ, flag, off;
    extract_addrentry(t.dyn->arg1, typ, flag, off);

    if (flag != IRRELEVANT) {
        switch (typ) {
            case GREG:
                uses.insert("REG_" + std::to_string(t.dyn->arg2));
                break;
            case MADDR:
                //printf("Warning: what is MADDR? Val=%llx\n", t.dyn->arg2);
                uses.insert("HOST_" + std::to_string(t.dyn->arg2));
                break;
            case GSPEC:
                uses.insert("SPEC_" + std::to_string(t.dyn->arg2));
                break;
            default:
                printf("Warning: unhandled address entry type %d\n", typ);
                break;
        }
    }
    // Even IRRELEVANT loads can define things
    defs.insert(get_value_name(t.insn));
    return;
}

static void handleDefault(trace_entry &t,
        std::set<std::string> &uses,
        std::set<std::string> &defs) {
    for (User::op_iterator i = t.insn->op_begin(), e = t.insn->op_end(); i != e; ++i) {
        Value *v = *i;
        if (!isa<Constant>(v) && !isa<BasicBlock>(v)) { // No need to include constants
            uses.insert(get_value_name(*i));
        }
    }
    defs.insert(get_value_name(t.insn));
    return;
}

static void handleCall(trace_entry &t,
        std::set<std::string> &uses,
        std::set<std::string> &defs) {
    CallInst *c = cast<CallInst>(t.insn);
    StringRef func_name = c->getCalledFunction()->getName();
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
            char name[128];
            sprintf(name, "MEM_%llx", t.dyn->arg2 + off);
            uses.insert(name);
        }
        Value *load_addr = c->getArgOperand(0);
        if (!isa<Constant>(load_addr)) uses.insert(get_value_name(load_addr));
        defs.insert(get_value_name(t.insn));
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
            char name[128];
            sprintf(name, "MEM_%llx", t.dyn->arg2 + off);
            defs.insert(name);
        }
        Value *store_addr = c->getArgOperand(0);
        Value *store_val  = c->getArgOperand(1);
        if (!isa<Constant>(store_addr)) uses.insert(get_value_name(store_addr));
        if (!isa<Constant>(store_val)) uses.insert(get_value_name(store_val));
    }
    else if (func_name.startswith("llvm.memcpy")) { } // TODO
    else if (func_name.startswith("llvm.memset")) {

    } // TODO
    else if (func_name.startswith("helper_in")) { } // TODO
    else if (func_name.startswith("helper_out")) { } // TODO
    else if (func_name.startswith("log_dynval")) {
        // ignore
    }
    else {
        // call to some helper
        handleDefault(t, uses, defs);
    }
    return;
}

// I don't *think* we can use LLVM's InstructionVisitor here because actually
// want to operate on a trace element, not an Instruction (and hence we need
// the accompanying dynamic info).
void get_uses_and_defs(trace_entry &t,
        std::set<std::string> &uses,
        std::set<std::string> &defs) {
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
        case Instruction::Br:
        case Instruction::Switch:
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::IntToPtr:
        case Instruction::PtrToInt:
        case Instruction::And:
        case Instruction::Xor:
        case Instruction::Or:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::Trunc:
        case Instruction::GetElementPtr:
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr:
        case Instruction::ICmp:
            handleDefault(t, uses, defs);
            return;
        case Instruction::Ret:
        case Instruction::Alloca:
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

void print_marked(Function *f) {
    printf("*** Function %s ***\n", f->getName().str().c_str());
    int i = 0;
    for (Function::iterator it = f->begin(), ed = f->end(); it != ed; ++it) {
        printf(">>> Block %d\n", i);
        int j = 0;
        for (BasicBlock::iterator insn_it = it->begin(), insn_ed = it->end(); insn_it != insn_ed; ++insn_it) {
            char m = marked[std::make_pair(f,i)][j] ? '*' : ' ';
            fprintf(stderr, "%c ", m);
            insn_it->dump();
            j++;
        }
        i++;
    }
}

void mark(trace_entry &t) {
    int bb_num = t.index >> 16;
    int insn_index = t.index & 0xffff;
    assert (insn_index < MAX_BITSET);
    marked[std::make_pair(t.func,bb_num)][insn_index] = true;
    if (debug) printf("Marking %s, block %d, instruction %d.\n", t.func->getName().str().c_str(), bb_num, insn_index);
}

void print_insn(Instruction *insn) {
    std::string s;
    raw_string_ostream ss(s);
    insn->print(ss);
    ss.flush();
    printf("%s\n", ss.str().c_str());
    return;
}

// Core slicing algorithm. If the current instruction
// defines something we currently care about, then kill
// the defs and add in the uses.
// Note that this *modifies* the working set 'work' and
// updates the global map of LLVM functions => bitsets
void slice_trace(std::vector<trace_entry> &trace,
        std::set<std::string> &work) {
    Function *entry_func = trace[0].func;

    for(std::vector<trace_entry>::reverse_iterator it = trace.rbegin();
            it != trace.rend(); it++) {
        // Skip helper functions for now
        if (it->func != entry_func) continue;
        if (debug) printf(">> %s\n", it->insn->getOpcodeName());
        if (debug) print_insn(it->insn);

        //it->insn->dump();
        std::set<std::string> uses, defs;
        get_uses_and_defs(*it, uses, defs);

        if (debug) printf("DEBUG: %d defs, %d uses\n", defs.size(), uses.size());
        if (debug) printf("DEFS: {");
        if (debug) for (auto &w : defs) printf(" %s", w.c_str());
        if (debug) printf(" }\n");
        if (debug) printf("USES: {");
        if (debug) for (auto &w : uses) printf(" %s", w.c_str());
        if (debug) printf(" }\n");
        
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
        else if (it->insn->isTerminator() && !isa<ReturnInst>(it->insn) && INCLUDE_BRANCHES) {
            // Special case: branch/switch
            if (debug) printf("Current instruction is a branch, adding it.\n");
            mark(*it);
            work.insert(uses.begin(), uses.end());
        }

        if (debug) printf("Working set: {");
        if (debug) for (auto &w : work) printf(" %s", w.c_str());
        if (debug) printf(" }\n");

    }
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

TUBTEntry * process_func(Function *f, TUBTEntry *dynvals, std::vector<trace_entry> *serialized) {
    assert(serialized != NULL);
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
                // if (debug) printf("Found exception, will not finish this function.\n");
                in_exception = true;
                cursor++;
                return cursor;
            }

            // if (debug) errs() << *i << "\n";

            switch (i->getOpcode()) {
                case Instruction::Load: {
                    assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                    LoadInst *l = cast<LoadInst>(&*i);
                    // if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized->push_back(t);
                    cursor++;
                    break;
                }
                case Instruction::Store: {
                    StoreInst *s = cast<StoreInst>(&*i);
                    if (!s->isVolatile()) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        // if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
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
                    serialized->push_back(t);
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
                    serialized->push_back(t);
                    cursor++;
                    have_successor = true;
                    break;
                }
                case Instruction::Select: {
                    assert(cursor->type == TUBTFE_LLVM_DV_SELECT);
                    SelectInst *s = cast<SelectInst>(&*i);
                    if (debug) dump_tubt(cursor);
                    t.func = f; t.insn = i; t.dyn = cursor;
                    serialized->push_back(t);
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
                        serialized->push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("__st")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memcpy")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
                        cursor++;
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.dyn2 = cursor;
                        cursor++;
                    }
                    else if (func_name.startswith("llvm.memset")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("helper_in")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_LOAD);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
                        cursor++;
                    }
                    else if (func_name.startswith("helper_out")) {
                        assert(cursor->type == TUBTFE_LLVM_DV_STORE);
                        if (debug) dump_tubt(cursor);
                        t.func = f; t.insn = i; t.dyn = cursor;
                        serialized->push_back(t);
                        cursor++;
                    }
                    else if (func_name.equals("log_dynval") ||
                             subf->isDeclaration() ||
                             subf->isIntrinsic()) {
                        // ignore
                    }
                    else {
                        t.func = f; t.insn = i; t.dyn = NULL;
                        serialized->push_back(t);
                        // descend
                        cursor = process_func(subf, cursor, serialized);
                    }
                    break;
                }
                default:
                    t.func = f; t.insn = i; t.dyn = NULL;
                    serialized->push_back(t);
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
   fprintf(stderr, "Usage: %s [-d] [-p PC] [-n NUM] <llvm_mod> <dynlog> <criterion> [<criterion> ...]\n",
           prog);
}

int main(int argc, char **argv) {
    // mmap the dynamic log

    int opt;
    unsigned long num, pc;
    bool have_num = false, have_pc = false;
    while ((opt = getopt(argc, argv, "dn:p:")) != -1) {
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

    char *llvm_mod_fname = argv[optind];
    char *tubt_log_fname = argv[optind+1];

    // Add the slicing criteria
    std::set<std::string> work;
    for (int i = optind + 2; i < argc; i++) {
        work.insert(argv[i]);
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
        cursor = process_func(f, cursor, &aligned_block);

        // And slice it
        slice_trace(aligned_block, work);

        rows_processed = cursor - rows;
        update_progress(rows_processed, num_rows);
    }

    printf("\n");

    uint64_t insns_marked = 0;
    for (auto &kvp : marked) insns_marked += kvp.second.size();
    printf("Done slicing. Marked %llu blocks, %llu instructions.\n", marked.size(), insns_marked);

    return 0;
}

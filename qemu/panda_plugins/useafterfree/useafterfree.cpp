// Use after free detector. -ph
// Designed to target RtlAllocateHeap, RtlFreeHeap, RtlReAllocateHeap on Windows.
// Should be easily adaptable to other systems.
// Use the command-line args to specify entry points for Rtl functions; plugin
// will do the rest of the work.

#define __STDC_FORMAT_MACROS

extern "C" {

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "panda_common.h"

#include "rr_log.h"

#include "../callstack_instr/callstack_instr.h"

#include <stdio.h>
#include <dlfcn.h>

bool init_plugin(void *);
void uninit_plugin(void *);
int virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int virt_mem_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int before_block_exec(CPUState *env, TranslationBlock *tb);

}

#include <map>
#include <stack>
#include <set>
#include <tuple>

// hack to avoid warnings about printf formats... sorry.
#if defined(TARGET_I386) && TARGET_LONG_SIZE == 8
// Necessary information to keep track of an alloc call on the stack.
struct alloc_info {
    target_ulong heap;
    target_ulong size;
    target_ulong retaddr;
};

// Ditto for free
struct free_info {
    target_ulong heap;
    target_ulong addr;
    target_ulong retaddr;
};

struct realloc_info {
    target_ulong heap;
    target_ulong addr;
    target_ulong size;
    target_ulong retaddr;
};

static bool print = false;

static target_ulong alloc_guest_addr, free_guest_addr, realloc_guest_addr;
static target_ulong right_cr3;
static int word_size;

// Set of ranges [begin, end).
// Should satisfy guarantee that all ranges are disjoint at all times.
struct range_set {
    std::map<target_ulong, target_ulong> impl; // map from range begin -> end

    bool insert(target_ulong begin, target_ulong end, bool merge = true) {
        bool error = false;

        // Unify on left.
        auto it = impl.upper_bound(begin);
        if (it != impl.begin()) {
            it--; // now points to greatest elt <= begin
            if (begin < it->second) { // overlap! unify.
                if (!merge) {
                    printf("error! we shouldn't be merging [ %lx, %lx ). assuming missed free of [ %lx, %lx ).\n", begin, end, it->first, it->second);
                    error = true;
                } else {
                    begin = it->first;
                    end = std::max(end, it->second);
                }
                impl.erase(it->first);
            }
        }
        
        // Unify on right.
        it = impl.upper_bound(begin); // least elt > (begin, end);
        if (it != impl.end()) {
            if (end > it->first) { // overlap! unify.
                if (!merge) {
                    printf("error! we shouldn't be merging. assuming missed free.\n");
                    error = true;
                } else {
                    end = std::max(end, it->second);
                }
                impl.erase(it->first);
            }
        }

        impl[begin] = end;

        return error;
    }

    bool contains(target_ulong addr) {
        if (impl.empty()) return false;
        else {
            auto it = impl.upper_bound(addr);
            it--; // now greatest <= addr
            return addr >= it->first && addr < it->second;
        }
    }

    bool has_range(target_ulong begin) {
        return impl.count(begin) > 0;
    }

    void resize(target_ulong begin, target_ulong new_end) {
        if (impl.count(begin) > 0) {
            impl[begin] = new_end;
        } else {
            printf("error! resizing nonexistent range @ %lx\n", begin);
        }
    }

    target_ulong lookup(target_ulong begin) {
        if (impl.count(begin) > 0) {
            return impl[begin];
        } else {
            printf("error! lookup on nonexistent range @ %lx\n", begin);
            return 0;
        }
    }

    // We will only ever use this with alloc_now, which should never have an
    // overlapping range inserted. So we can implement this the easy way.
    void remove(target_ulong begin) {
        if (impl.count(begin) == 0) {
            printf("error! %lx not found!\n", begin);
            if (print) dump();

            auto it = impl.upper_bound(begin);
            if (it != impl.begin()) {
                it--;
                if (false) {// begin < it->second) {
                    printf("freeing containing block.\n");
                    impl.erase(it->first);
                }
            }
        } else {
            impl.erase(begin);
        }
    }

    void dump() {
        printf("{  ");
        for (auto it = impl.begin(); it != impl.end(); it++) {
            printf("[ %lx, %lx ) ", it->first, it->second);
        }
        printf(" }\n");
    }
};

// These are all per-cr3 data structs.
static std::map<target_ulong, std::map<target_ulong, range_set>> alloc_now; // Allocated now.
static std::map<target_ulong, std::map<target_ulong, range_set>> alloc_ever; // Allocated ever.
static std::map<target_ulong, std::stack<alloc_info>> alloc_stacks; // Track alloc callstack.
static std::map<target_ulong, std::stack<free_info>> free_stacks; // Track free callstack.
static std::map<target_ulong, std::stack<realloc_info>> realloc_stacks; // Reallocs

static int debug = 0;

static int virt_mem_access(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf, int is_write);

void process_call(CPUState *env, TranslationBlock *tb, TranslationBlock *next);
void process_ret(CPUState *env, TranslationBlock *tb, TranslationBlock *next);

bool is_right_proc(CPUState *env) {
    if ((env->hflags & HF_CPL_MASK) == 0) return false;
    else return (env->cr[3] == right_cr3);
}

void process_call(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    /*if (!is_right_proc(env)) return;

    uint8_t buf[6];
    //uint8_t call_free[6] = {0xFF, 0x15, 0x30, 0x16, 0xDB, 0x76};
    uint8_t call_realloc[6] = {0xFF, 0x15, 0x78, 0x13, 0x9A, 0x6B};
    panda_virtual_memory_rw(env, tb->pc + tb->size - 6, buf, 6, 0);

    //printf("call: from tb @ %08x, size %x. eip %08x now.\n", tb->pc, tb->size, env->eip);

    if (memcmp(buf, call_realloc, 6) == 0) {
        debug = 30;
        printf("realloc!!!  ");
    }
    } else if (memcmp(buf, call_alloc, 6) == 0) {
        //printf("found alloc!\n");

        alloc_retaddr = tb->pc + tb->size;

        debug = 100;
    }*/
}

void process_ret(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    if (!is_right_proc(env)) return;

    target_ulong cr3 = env->cr[3];

    //printf("ret! %lx\n", env->eip);
    if (!alloc_stacks[cr3].empty() && env->eip == alloc_stacks[cr3].top().retaddr) {
        alloc_info info = alloc_stacks[cr3].top();
        target_ulong addr = env->regs[R_EAX];
        if (!(alloc_stacks[cr3].size() == 2 && (info.size & 0x3ff) == 0x3f8)) {
            // Otherwise RtlAllocateHeap is calling itself to get a big block
            // to split up into little blocks. No idea why. -ph
            alloc_now[cr3][info.heap].insert(addr, addr + info.size, false);
            alloc_ever[cr3][info.heap].insert(addr, addr + info.size);
        }
        if (print) {
            printf("PP %lu: return from alloc; addr {%lx, %lx}, size %lx\n", rr_prog_point.guest_instr_count, env->cr[3], env->regs[R_EAX], info.size);
            printf("    alloc_now: ");
            alloc_now[cr3][info.heap].dump();
            printf("    alloc_ever: ");
            alloc_ever[cr3][info.heap].dump();
            printf("\n");
        }
        alloc_stacks[cr3].pop();
    } else if (!free_stacks[cr3].empty() && env->eip == free_stacks[cr3].top().retaddr) {
        free_info info = free_stacks[cr3].top();
        if (info.addr > 0 && alloc_ever[cr3][info.heap].contains(info.addr)) {
            if (!alloc_now[cr3][info.heap].contains(info.addr)) {
                printf("DOUBLE FREE @ {%lx, %lx}! PC %lx\n", cr3, info.addr, env->eip);
            } else {
                alloc_now[cr3][info.heap].remove(info.addr);
            }
        }
        if (print) {
            printf("PP %lu: return from free; addr {%lx, %lx}!\n", rr_prog_point.guest_instr_count, env->cr[3], info.addr);
            printf("    alloc_now: ");
            alloc_now[cr3][info.heap].dump();
            printf("\n");
        }

        free_stacks[cr3].pop();
    } else if (!realloc_stacks[cr3].empty() && env->eip == realloc_stacks[cr3].top().retaddr) {
        realloc_info info = realloc_stacks[cr3].top();
        target_ulong newaddr = env->regs[R_EAX];

        if (!newaddr) {
            printf("error! realloc failed!\n");
            return;
        }

        if (alloc_now[cr3][info.heap].has_range(info.addr)) { // check original range
            if (info.addr == newaddr) {
                alloc_now[cr3][info.heap].resize(info.addr, info.addr + info.size);
            } else {
                alloc_now[cr3][info.heap].remove(info.addr);
            }
        } 
        if (!alloc_now[cr3][info.heap].has_range(newaddr)) { // check new range
            alloc_now[cr3][info.heap].insert(newaddr, newaddr + info.size);
        } else {
            alloc_now[cr3][info.heap].resize(newaddr, newaddr + info.size);
        }

        //alloc_now[cr3][info.heap].dump();

        //printf("realloc @ %lx to %lx, size %lx!\n", info.addr, newaddr, info.size);
    }
}

static bool inside_memop(target_ulong cr3) {
    return !(alloc_stacks[cr3].empty() && free_stacks[cr3].empty());
}

static int virt_mem_access(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf, int is_write) {
    target_ulong cr3 = env->cr[3];
    if (!inside_memop(cr3) && pc >> 20 != alloc_guest_addr >> 20) { // hack.
        for (auto it = alloc_ever[cr3].begin(); it != alloc_ever[cr3].end(); it++) {
            if (alloc_ever[cr3][it->first].contains(addr)
                    && !alloc_now[cr3][it->first].contains(addr)) {
                //range_set ae = alloc_ever[cr3][it->first];
                //range_set an = alloc_now[cr3][it->first];
                printf("USE AFTER FREE %s @ {%lx, %lx}! PC %lx\n",
                        is_write ? "WRITE" : "READ", cr3, addr, pc);
                break;
            }
        }
    }

    return 0;
}

int virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return virt_mem_access(env, pc, addr, size, buf, 1);
}

int virt_mem_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return virt_mem_access(env, pc, addr, size, buf, 0);
}

// Returns [esp + word_size*offset_number]
// Assumes target+host have same endianness.
static target_ulong get_stack(CPUState *env, int offset_number) {
    target_ulong result = 0;
    panda_virtual_memory_rw(env, env->regs[R_ESP] + word_size * offset_number,
            (uint8_t *)&result, word_size, 0);
    return result;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (!is_right_proc(env)) return 0;

    target_ulong cr3 = env->cr[3];

    if (debug > 0) {
        printf("%lx ", tb->pc);
        debug--;
        if (debug == 0) printf("\n");
    }

    if (tb->pc == free_guest_addr) { // free
        free_info info;
        info.retaddr = get_stack(env, 0);
        info.heap = get_stack(env, 1);
        info.addr = get_stack(env, 3);
        free_stacks[cr3].push(info);

        //printf("found free @ %lx! ret to %lx\n", free_addr.addr, free_retaddr.addr);
    } else if (tb->pc == alloc_guest_addr) { // alloc
        //printf("found alloc!\n");
        
        alloc_info info;
        info.retaddr = get_stack(env, 0);
        info.heap = get_stack(env, 1);
        info.size = get_stack(env, 3);
        alloc_stacks[cr3].push(info);

        if (alloc_stacks[cr3].size() > 2) {
            printf("stack size > 2!!!!! unexpected!!\n");
        }

        //debug = 100;
    } else if (tb->pc == realloc_guest_addr) { // realloc
        realloc_info info;
        info.retaddr = get_stack(env, 0);
        info.heap = get_stack(env, 1);
        info.addr = get_stack(env, 3);
        info.size = get_stack(env, 4);
        realloc_stacks[cr3].push(info);

        //debug = 40;
    }
        

    return 0;
}

#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) && TARGET_LONG_SIZE == 8
    PPP_REG_CB("callstack_instr", on_call, process_call);
    PPP_REG_CB("callstack_instr", on_ret, process_ret);

    panda_enable_memcb();
    panda_cb pcb;
    pcb.virt_mem_write = virt_mem_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = virt_mem_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("useafterfree");

    // Addresses for alloc/free/realloc
    alloc_guest_addr = panda_parse_ulong(args, "alloc", 0x77D72DD6);
    free_guest_addr = panda_parse_ulong(args, "free", 0x77D72C6A);
    realloc_guest_addr = panda_parse_ulong(args, "realloc", 0x77D8FF51);
    // CR3 to watch.
    right_cr3 = panda_parse_ulong(args, "cr3", 0x7F893460);
    // Size of words on target OS.
    word_size = panda_parse_uint64(args, "word", 4);

    printf("Looking for alloc @ %lx, free @ %lx, realloc @ %lx\n",
            alloc_guest_addr, free_guest_addr, realloc_guest_addr);

#endif

    return true;
}

void uninit_plugin(void *self) { }

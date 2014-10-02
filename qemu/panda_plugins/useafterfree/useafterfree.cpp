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

bool init_plugin(void *);
void uninit_plugin(void *);
int virt_mem_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int virt_mem_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int before_block_exec(CPUState *env, TranslationBlock *tb);

}

#include <map>
#include <stack>
#include <set>
#include <queue>

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
static bool ptrprint = false;

static target_ulong alloc_guest_addr, free_guest_addr, realloc_guest_addr;
static target_ulong right_cr3;
static unsigned word_size;

struct range_info {
    target_ulong heap, begin, end;
    std::set<target_ulong> valid_ptrs; // Addresses of valid ptrs to this range

    range_info(target_ulong heap_, target_ulong begin_, target_ulong end_) {
        heap = heap_; begin = begin_; end = end_;
    }
    range_info() {
        heap = 0; begin = 0; end = 0;
    }
};

struct merge_range_set {
    std::map<target_ulong, target_ulong> impl;

    void insert(target_ulong heap, target_ulong begin, target_ulong end) {
        auto it = impl.upper_bound(begin); // first range past begin
        if (it != impl.begin()) { // possible overlap on left. have to handle.
            it--;
            if (begin < it->second) {
                begin = std::min(begin, it->first);
                it = impl.erase(it);
            } else {
                it++;
            }
        }
        // Erase all subranges.
        while (it != impl.end() && end > it->second) {
            it = impl.erase(it);
        }
        // Handle right overlap. At this point should have end <= it->second
        if (it != impl.end()) {
            if (end >= it->first) { // merge when touching, even. performance.
                end = std::max(end, it->second);
                impl.erase(it);
            }
        }
        impl[begin] = end;
    }

    bool contains(target_ulong addr) {
        if (impl.empty()) return false;
        else {
            auto it = impl.upper_bound(addr);
            if (it != impl.begin()) it--; // now greatest <= addr
            return addr >= it->first && addr < it->second;
        }
    }

    void dump() {
        printf("{  ");
        for (auto it = impl.begin(); it != impl.end(); it++) {
            printf("[%lx, %lx) ", it->first, it->second);
        }
        printf(" }\n");
    }
};

// Set of ranges [begin, end).
// Should satisfy guarantee that all ranges are disjoint at all times.
struct range_set {
    std::map<target_ulong, range_info> impl; // map from range begin -> end

    bool insert(target_ulong heap, target_ulong begin, target_ulong end) {
        bool error = false;

        // Check left overlap. FIXME make sure this is correct.
        auto it = impl.upper_bound(begin);
        if (it != impl.begin()) {
            it--; // now points to greatest elt <= begin
            if (begin < it->second.end) {
                printf("error! we shouldn't be merging [ %lx, %lx ). assuming missed free of [ %lx, %lx ).\n", begin, end, it->first, it->second.end);
                error = true;
                impl.erase(it->first);
            }
        }

        // Check right overlap.
        it = impl.upper_bound(begin); // least elt > (begin, end);
        if (it != impl.end()) {
            if (end > it->first) {
                printf("error! we shouldn't be merging. assuming missed free.\n");
                error = true;
                impl.erase(it->first);
            }
        }

        range_info ri(heap, begin, end);
        impl[begin] = ri;

        return error;
    }

    bool contains(target_ulong addr) {
        if (impl.empty()) return false;
        else {
            auto it = impl.upper_bound(addr);
            if (it != impl.begin()) it--; // now greatest <= addr
            return addr >= it->first && addr < it->second.end;
        }
    }

    bool has_range(target_ulong begin) {
        return impl.count(begin) > 0;
    }

    void resize(target_ulong begin, target_ulong new_end) {
        if (impl.count(begin) > 0) {
            range_info &ri = impl[begin];
            ri.end = new_end;
        } else {
            printf("error! resizing nonexistent range @ %lx\n", begin);
        }
    }

    range_info& operator[](target_ulong addr) {
        if (impl.count(addr) > 0) return impl[addr];
        auto it = impl.upper_bound(addr);
        if (it != impl.begin()) {
            it--; // now points to greatest elt <= addr
            if (addr >= it->first && addr < it->second.end) {
                return it->second;
            }
        }
        printf("error! lookup on nonexistent addr %lx\n", addr);
        throw 0;
    }

    // We will only ever use this with alloc_now, which should never have an
    // overlapping range inserted. So we can implement this the easy way.
    void remove(target_ulong begin) {
        if (impl.count(begin) == 0) {
            printf("error! %lx not found!\n", begin);
            dump();

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
            printf("%lx:[%lx, %lx) ", it->second.heap, it->first, it->second.end);
        }
        printf(" }\n");
    }
};

struct read_info {
    target_ulong pc, loc, val;
    read_info(target_ulong pc_, target_ulong loc_, target_ulong val_) {
        pc = pc_; loc = loc_; val = val_;
    }
};

// These are all per-cr3 data structs.
static std::map<target_ulong, range_set> alloc_now; // Allocated now.
static std::map<target_ulong, merge_range_set> alloc_ever; // Allocated ever.
static std::map<target_ulong, std::stack<alloc_info>> alloc_stacks; // Track alloc callstack.
static std::map<target_ulong, std::stack<free_info>> free_stacks; // Track free callstack.
static std::map<target_ulong, std::stack<realloc_info>> realloc_stacks; // Reallocs
// Map from pointer location to instr count of invalidation
static std::map<target_ulong, std::map<target_ulong, uint64_t>> invalid_ptrs;
// Map from cr3 => map from pointer location => pointer value
static std::map<target_ulong, std::map<target_ulong, target_ulong>> valid_ptrs;
static std::map<target_ulong, std::queue<target_ulong>> invalid_queue;
static std::map<target_ulong, std::queue<read_info>> bad_read_queue;

static int debug = 0;

static const unsigned safety_window = 1000000;

static int virt_mem_access(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf, int is_write);

void process_ret(CPUState *env, target_ulong func);

bool is_right_proc(CPUState *env) {
    if ((env->hflags & HF_CPL_MASK) == 0) return false;
    else return (env->cr[3] == right_cr3);
}

static bool inside_memop(target_ulong cr3) {
    return !(alloc_stacks[cr3].empty() && free_stacks[cr3].empty());
}

// Assumes target+host have same endianness.
static target_ulong get_word(CPUState *env, target_ulong addr) {
    target_ulong result = 0;
    panda_virtual_memory_rw(env, addr, (uint8_t *)&result, word_size, 0);
    return result;
}

// Returns [esp + word_size*offset_number]
static target_ulong get_stack(CPUState *env, int offset_number) {
    return get_word(env, env->regs[R_ESP] + word_size * offset_number);
}

void process_ret(CPUState *env, target_ulong func) {
    if (!is_right_proc(env)) return;

    target_ulong cr3 = env->cr[3];

    //printf("ret! %lx\n", env->eip);
    if (!alloc_stacks[cr3].empty() && env->eip == alloc_stacks[cr3].top().retaddr) {
        alloc_info info = alloc_stacks[cr3].top();
        target_ulong addr = env->regs[R_EAX];
        if (!(alloc_stacks[cr3].size() == 2 && (info.size & 0x3ff) == 0x3f8)) {
            // Otherwise RtlAllocateHeap is calling itself to get a big block
            // to split up into little blocks. No idea why. -ph
            if (addr != 0) {
                alloc_now[cr3].insert(info.heap, addr, addr + info.size);
                alloc_ever[cr3].insert(info.heap, addr, addr + info.size);
            }
        }
        if (print) {
            printf("PP %lu: return from alloc; addr {%lx, %lx}, size %lx\n", rr_prog_point.guest_instr_count, env->cr[3], env->regs[R_EAX], info.size);
            printf("    alloc_now: ");
            alloc_now[cr3].dump();
            printf("    alloc_ever: ");
            alloc_ever[cr3].dump();
            printf("\n");
        }
        alloc_stacks[cr3].pop();
    } else if (!free_stacks[cr3].empty() && env->eip == free_stacks[cr3].top().retaddr) {
        free_info info = free_stacks[cr3].top();
        if (info.addr > 0 && alloc_ever[cr3].contains(info.addr)) {
            if (!alloc_now[cr3].contains(info.addr)) {
                if (!inside_memop(cr3) && func >> 20 != alloc_guest_addr >> 20)
                    printf("DOUBLE FREE @ {%lx, %lx}! PC %lx\n", cr3, info.addr, env->eip);
            } else if (free_stacks[cr3].size() == 1) {
                range_info &ri = alloc_now[cr3][info.addr];
                for (auto it = ri.valid_ptrs.begin(); it != ri.valid_ptrs.end(); it++) {
                    if (ptrprint) printf("Invalidating pointer @ %lx\n", *it);
                    // *it is the location of a pointer into the freed range
                    if (alloc_now[cr3].contains(*it)) {
                        invalid_queue[cr3].push(*it);
                    }
                    invalid_ptrs[cr3][*it] = rr_get_guest_instr_count();
                    valid_ptrs[cr3].erase(*it);
                }
                alloc_now[cr3].remove(info.addr);
            }
        }
        if (print) {
            printf("PP %lu: return from free; addr {%lx, %lx}!\n", rr_prog_point.guest_instr_count, env->cr[3], info.addr);
            printf("    alloc_now: ");
            alloc_now[cr3].dump();
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

        if (alloc_now[cr3].has_range(info.addr)) { // check original range
            if (info.addr == newaddr) {
                alloc_now[cr3].resize(info.addr, info.addr + info.size);
            } else {
                if (alloc_now[cr3].contains(info.addr)) {
                    printf("error! realloc isn't tracking ptrs.\n");
                }
                alloc_now[cr3].remove(info.addr);
            }
        }
        if (!alloc_now[cr3].has_range(newaddr)) { // check new range
            alloc_now[cr3].insert(info.heap, newaddr, newaddr + info.size);
        } else {
            alloc_now[cr3].resize(newaddr, newaddr + info.size);
        }

        //alloc_now[cr3].dump();

        //printf("realloc @ %lx to %lx, size %lx!\n", info.addr, newaddr, info.size);
    }
}

static int virt_mem_access(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf, int is_write) {
    if (!is_right_proc(env)) return 0;

    target_ulong cr3 = env->cr[3];

    if (size >= word_size && is_write) { // The addresses we're overwriting don't contain ptrs anymore.
        target_ulong begin = addr, end = addr + size;
        auto end_it = valid_ptrs[cr3].lower_bound(end);
        for (auto it = valid_ptrs[cr3].lower_bound(begin); it != end_it;
                it = valid_ptrs[cr3].erase(it)) {
            // it->second is the value of a ptr. it->first is its location.
            if (alloc_now[cr3].contains(it->second)) {
                if (ptrprint) printf("Erasing pointer to %lx @ %lx.\n", it->second, it->first);
                alloc_now[cr3][it->second].valid_ptrs.erase(it->first);
            }
        }

        auto end_it2 = invalid_ptrs[cr3].lower_bound(end);
        for (auto it = invalid_ptrs[cr3].lower_bound(begin); it != end_it2;
                it = invalid_ptrs[cr3].erase(it)) {
            if (ptrprint) printf("Erasing invalid pointer @ %lx.\n", it->first);
        }
    }

    if (!inside_memop(cr3) && pc >> 20 != alloc_guest_addr >> 20) { // hack.
        if (alloc_ever[cr3].contains(addr)
                && !alloc_now[cr3].contains(addr)) {
            //range_set ae = alloc_ever[cr3][it->first];
            //range_set an = alloc_now[cr3][it->first];
            printf("USE AFTER FREE %s @ {%lx, %lx}! PC %lx\n",
                    is_write ? "WRITE" : "READ", cr3, addr, pc);
            //panda_memsavep(fopen("uaf.raw", "w"));
            return 0;
        }

        if (size == word_size) {
            target_ulong loc = addr; // Pointer location
            // Pointer value; should be address inside valid range
            target_ulong val = *(uint32_t *)buf;
            // Might be writing a pointer. Track.
            if (is_write) {
                if (alloc_now[cr3].contains(val)) { // actually creating pointer.
                    if (ptrprint) printf("Creating pointer to %lx @ %lx.\n", val, loc);
                    alloc_now[cr3][val].valid_ptrs.insert(loc);
                    try { valid_ptrs[cr3][loc] = val; } catch (int e) {}
                } else if (alloc_ever[cr3].contains(val)) {
                    // Oops! We wrote an invalid pointer.
                    if (ptrprint) printf("Writing invalid pointer to %lx @ %lx.\n", val, loc);
                    invalid_ptrs[cr3][loc] = rr_get_guest_instr_count();
                }
            } else if (env->regs[R_ESP] != loc) { // Reading a pointer. Ignore stack reads.
                // Leave safety window.
                if (invalid_ptrs[cr3].count(loc) > 0 &&
                        rr_get_guest_instr_count() - invalid_ptrs[cr3][loc] > safety_window &&
                        val != 0) {
                    bad_read_queue[cr3].push(read_info(pc, loc, val));
                }
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

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (!is_right_proc(env)) return 0;

    target_ulong cr3 = env->cr[3];

    if (debug > 0) {
        printf("%lx ", tb->pc);
        debug--;
        if (debug == 0) printf("\n");
    }

    // Clear queue of potential bad reads.
    while (bad_read_queue[cr3].size() > 0) {
        read_info& ri = bad_read_queue[cr3].front();
        if (get_word(env, ri.loc) == ri.val) { // Still invalid.
            printf("READING INVALID POINTER %lx @ %lx!! PC %lx\n", ri.val, ri.loc, ri.pc);
        }
        bad_read_queue[cr3].pop();
    }

    // Clear queue of potential dangling pointers.
    while (invalid_queue[cr3].size() > 0) {
        target_ulong loc = invalid_queue[cr3].front();

        if (invalid_ptrs[cr3].count(loc) == 0 || !alloc_now[cr3].contains(loc)) {
            // Pointer has been overwritten or deallocated; not dangling.
            invalid_queue[cr3].pop();
            continue;
        }
        if (rr_get_guest_instr_count() - invalid_ptrs[cr3][loc] <= safety_window) {
            // Inside safety window still.
            break;
        }

        // Outside safety window and pointer is still dangling. Report.
        printf("POINTER RETENTION to %lx @ %lx!\n", get_word(env, loc), loc);
        invalid_queue[cr3].pop();
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
    alloc_guest_addr = panda_parse_ulong(args, "alloc", 0x7787209D);
    free_guest_addr = panda_parse_ulong(args, "free", 0x77871F31);
    realloc_guest_addr = panda_parse_ulong(args, "realloc", 0x77877E54);
    // CR3 to watch.
    right_cr3 = panda_parse_ulong(args, "cr3", 0x3F98B320);
    // Size of words on target OS.
    word_size = panda_parse_uint64(args, "word", 4);

    printf("Looking for alloc @ %lx, free @ %lx, realloc @ %lx\n",
            alloc_guest_addr, free_guest_addr, realloc_guest_addr);

#endif

    return true;
}

void uninit_plugin(void *self) { }

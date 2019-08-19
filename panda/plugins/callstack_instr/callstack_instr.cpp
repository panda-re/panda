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
// Change Log
// 2018-MAY-29   move where mode bit calculated as requested
// 2018-APR-13   watch for x86 processor mode changing in i386 build
// 2019-JAN-29   do not put an entry in the callstack if the block was stopped
//               before the call at the end was made
// 2019-MAY-21   add (more accurate) stack segregation option (threaded)
#define __STDC_FORMAT_MACROS

#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstdlib>

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

// needed for the threaded stack_type
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"
#include "osi_linux/osi_linux_ext.h"

#include "callstack_instr.h"

extern "C" {
#include "panda/plog.h"
#include "callstack_instr_int_fns.h"

bool translate_callback(CPUState* cpu, target_ulong pc);
int exec_callback(CPUState* cpu, target_ulong pc);
int before_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_exec(CPUState* cpu, TranslationBlock *tb, uint8_t exitCode);
int after_block_translate(CPUState* cpu, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);
}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

stack_type stack_segregation = STACK_ASID;

// callstack_instr arguments
static bool verbose = false;

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    target_ulong pc;
    instr_type kind;
};

#define MAX_STACK_DIFF 5000

csh cs_handle_32;
csh cs_handle_64;

// Track the different stacks we have seen to handle multiple threads
// within a single process.  Used by STACK_HEURISTIC
std::map<target_ulong,std::set<target_ulong>> stacks_seen;

// For STACK_ASID, the first entry of the pair is the ASID, and the second is 0
// For STACK_HEURISTIC, the first entry is the ASID and the second is the SP
// For STACK_THREADED, the first entry is the process ID, the second is the
// thread ID, and the third is a flag to indicate kernel mode.
typedef std::tuple<target_ulong, target_ulong, bool> stackid;

// STACK_HEURISTIC also needs to cache the SP and ASID
target_ulong cached_sp = 0;
target_ulong cached_asid = 0;

// stackid -> shadow stack
std::map<stackid, std::vector<stack_entry>> callstacks;
// stackid -> function entry points
std::map<stackid, std::vector<target_ulong>> function_stacks;
// EIP -> instr_type
std::map<target_ulong, instr_type> call_cache;
// stackid -> address of Stopped block
std::map<stackid, target_ulong> stoppedInfo;

int last_ret_size = 0;

void verbose_log(const char *msg, TranslationBlock *tb, stackid curStackid,
        bool logReturn) {
    if (verbose) {
        printf("%s:  ", msg);
        if (STACK_HEURISTIC== stack_segregation) {
            // Kernel flag omitted, not required when using stack heuristic.
            printf("asid=0x" TARGET_FMT_lx ", sp=0x" TARGET_FMT_lx,
                   std::get<0>(curStackid), std::get<1>(curStackid));
        } else if (STACK_THREADED == stack_segregation) {
            printf("processID=0x" TARGET_FMT_lx ", threadID=0x" TARGET_FMT_lx
                   ", inKernel=%s",
                   std::get<0>(curStackid), std::get<1>(curStackid),
                   std::get<2>(curStackid) ? "true" : "false");
        } else {
            // STACK_ASID
            // Kernel flag omitted, not required when using asid stack type.
            printf("asid=0x" TARGET_FMT_lx, std::get<0>(curStackid));
        }
        printf(", block pc=0x" TARGET_FMT_lx, tb->pc);
        if (logReturn) {
            printf(", returns to 0x" TARGET_FMT_lx, (tb->pc+tb->size));
        }
        printf("\n");
    }
    // end of function verbose_log
}

static inline bool in_kernelspace(CPUArchState* env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static inline target_ulong get_stack_pointer(CPUArchState* env) {
#if defined(TARGET_I386)
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    return env->regs[13];
#else
    return 0;
#endif
}

// get the stackid when the heuristic stack segregation method is in use
// assumes stack_segregation is STACK_HEURISTIC
static stackid get_heuristic_stackid(CPUArchState* env) {
    // why is this part of get_stackid removed from it? to make SonarQube stop
    // complaining about get_stackid having too many return statements without
    // causing it to complain about if statements being nested too deep
    target_ulong asid;

    // Track all kernel-mode stacks together
    if (in_kernelspace(env)) {
        asid = 0;
    } else {
        asid = panda_current_asid(ENV_GET_CPU(env));
    }

    // Invalidate cached stack pointer on ASID change
    if ((0 == cached_asid) || (cached_asid != asid)) {
        cached_sp = 0;
        cached_asid = asid;
    }

    target_ulong sp = get_stack_pointer(env);
    stackid cursi;

    // We can short-circuit the search in most cases
    if (std::imaxabs(sp - cached_sp) < MAX_STACK_DIFF) {
        cursi = std::make_tuple(asid, cached_sp, 0);
    } else {
        auto &stackset = stacks_seen[asid];
        if (stackset.empty()) {
            stackset.insert(sp);
            cached_sp = sp;
            cursi = std::make_tuple(asid, sp, 0);
        }
        else {
            // Find the closest stack pointer we've seen
            auto lb = std::lower_bound(stackset.begin(), stackset.end(), sp);
            target_ulong stack1 = *lb;
            lb--;
            target_ulong stack2 = *lb;
            target_ulong stack = (std::imaxabs(stack1 - sp) < std::imaxabs(stack2 - sp)) ? stack1 : stack2;
            int diff = std::imaxabs(stack-sp);
            if (diff < MAX_STACK_DIFF) {
                cursi = std::make_tuple(asid, stack, 0);
            }
            else {
                stackset.insert(sp);
                cached_sp = sp;
                cursi = std::make_tuple(asid, sp, 0);
            }
        }
    }
    return cursi;
}

static stackid get_stackid(CPUArchState* env) {
    int in_kernel = in_kernelspace(env);
    if (STACK_HEURISTIC == stack_segregation) {
        return get_heuristic_stackid(env);
    } else if (STACK_THREADED == stack_segregation) {
        OsiThread *thr = get_current_thread(first_cpu);
        stackid cursi;
        if (NULL != thr) {
            cursi = std::make_tuple(thr->pid, thr->tid, in_kernel);
        } else {
            // assuming 0 is never a valid process ID and thread ID
            cursi = std::make_tuple(0, 0, in_kernel);
        }
        free_osithread(thr);
        return cursi;
    } else {
        // STACK_ASID
        target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
        return std::make_tuple(asid, 0, 0);
    }
    // end of function get_stackid
}

instr_type disas_block(CPUArchState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_CS64_MASK) ? cs_handle_64 : cs_handle_32;
#if !defined(TARGET_X86_64)
    // not every block in i386 is necessary executing in the same processor mode
    // need to make capstone match current mode or may miss call statements
    if ((env->hflags & HF_CS32_MASK) == 0) {
        cs_option(handle, CS_OPT_MODE, CS_MODE_16);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_32);
    }
#endif
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }

#elif defined(TARGET_PPC)
    csh handle = cs_handle_32;
#endif

    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);
    if (count <= 0) goto done2;

    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) goto done;

    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
        res = INSTR_CALL;
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
        res = INSTR_RET;
    } else {
        res = INSTR_UNKNOWN;
    }

done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);

    return 1;
}

int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    // if the block a call returns to was interrupted before it completed, this
    // function will be called twice - only want to remove the return value from
    // the stack once
    // the return value will have been removed before the attempt to run which
    // was stopped (as we didn't know it would be stopped then), so skip it on
    // the retry
    bool needToCheck = true;
    stackid curStackid = get_stackid(env);
    std::map<stackid, target_ulong>::const_iterator it;
    it = stoppedInfo.find(curStackid);
    if (it != stoppedInfo.end()) {
        target_ulong stoppedPC = stoppedInfo[curStackid];
        if (stoppedPC == tb->pc) {
            stoppedInfo.erase(it);
            needToCheck = false;
            verbose_log("callstack_instr skipping return check", tb, curStackid,
                    false);
        }
    }

    if (needToCheck) {
        std::vector<stack_entry> &v = callstacks[get_stackid(env)];
        std::vector<target_ulong> &w = function_stacks[get_stackid(env)];
        if (v.empty()) return 1;

        // Search up to 10 down
        for (int i = v.size()-1; i > ((int)(v.size()-10)) && i >= 0; i--) {
            if (tb->pc == v[i].pc) {
                //printf("Matched at depth %d\n", v.size()-i);
                //v.erase(v.begin()+i, v.end());

                PPP_RUN_CB(on_ret, cpu, w[i]);
                v.erase(v.begin()+i, v.end());
                w.erase(w.begin()+i, w.end());

                break;
            }
        }
    }


    return 0;
}

int after_block_exec(CPUState* cpu, TranslationBlock *tb, uint8_t exitCode) {
    target_ulong pc;
    target_ulong cs_base;
    uint32_t flags;

    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    instr_type tb_type = call_cache[tb->pc];
    stackid curStackid = get_stackid(env);

    // sometimes an attempt to run a block is interrupted, but this callback is
    // still made - only update the callstack if the block ran to completion
    if (exitCode <= TB_EXIT_IDX1) {
        // this attempt is OK, so remove it from the Stopped list, if there
        stoppedInfo.erase(curStackid);

        if (tb_type == INSTR_CALL) {
            stack_entry se = {tb->pc+tb->size,tb_type};
            callstacks[curStackid].push_back(se);

            // Also track the function that gets called
            // This retrieves the pc in an architecture-neutral way
            cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
            function_stacks[curStackid].push_back(pc);

            PPP_RUN_CB(on_call, cpu, pc);
        }
        else if (tb_type == INSTR_RET) {
            //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
            //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
        }
    }
    // in case this block is one that a call returns to, need to note that its
    // execution was interrupted, so don't try to remove it from the callstack
    // when retry (as already removed it before this attempt)
    else {
        // verbose output is helpful in regression testing
        if (tb_type == INSTR_CALL) {
            verbose_log("callstack_instr not adding Stopped caller to stack",
                    tb, curStackid, true);
        }

        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        // C++ maps don't let you replace value of an existing key (grr)
        // erase nicely does nothing if key DNE
        stoppedInfo.erase(curStackid);
        stoppedInfo[curStackid] = pc;
    }

    return 1;
}


/**
 * @brief Fills preallocated buffer \p callers with up to \p n call addresses.
 */
uint32_t get_callers(target_ulong callers[], uint32_t n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];

    n = std::min((uint32_t)v.size(), n);
    for (uint32_t i=0; i<n; i++) { callers[i] = v[v.size()-1-i].pc; }
    return n;
}


#define CALLSTACK_MAX_SIZE 16
/**
 * @brief Creates a pandalog entry with the callstack information.
 */
Panda__CallStack *pandalog_callstack_create() {
    assert(pandalog);
    CPUArchState* env = (CPUArchState*)first_cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];

    Panda__CallStack *cs = (Panda__CallStack *)malloc(sizeof(Panda__CallStack));
    *cs = PANDA__CALL_STACK__INIT;
    cs->n_addr = std::min((uint32_t)v.size(), (uint32_t)CALLSTACK_MAX_SIZE);
    cs->addr = (uint64_t *)malloc(cs->n_addr * sizeof(uint64_t));

    for (uint32_t i=0; i<cs->n_addr; i++) { cs->addr[i] = v[v.size()-1-i].pc; }

    return cs;
}


/**
 * @brief Frees a pandalog entry containing callstack information.
 */
void pandalog_callstack_free(Panda__CallStack *cs) {
    free(cs->addr);
    free(cs);
}


/**
 * @brief Fills preallocated buffer \p functions with up to \p n function addresses.
 */
uint32_t get_functions(target_ulong functions[], uint32_t n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<target_ulong> &v = function_stacks[get_stackid(env)];

    n = std::min((uint32_t)v.size(), n);
    for (uint32_t i=0; i<n; i++) { functions[i] = v[v.size()-1-i]; }
    return n;
}

void get_prog_point(CPUState* cpu, prog_point *p) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!p) return;

    // Get stack ID
    stackid curStackid = get_stackid(env);

    // Lump all kernel-mode CR3s together
    if(!in_kernelspace(env)) {
        p->sidFirst = std::get<0>(curStackid);
        p->sidSecond = std::get<1>(curStackid);
    }

    p->isKernelMode = std::get<2>(curStackid);
    p->stackKind = stack_segregation;

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, cpu);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(cpu, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
#endif
#ifdef TARGET_ARM
        p->caller = env->regs[14]; // LR
#endif

    }

    p->pc = cpu->panda_guest_pc;
}

// prepare OSI support that is needed for the threaded stack type
// returns true if set up OK, and false if it was not
bool setup_osi() {
    // moved out of init_plugin case statement to mollify SonarQube
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    printf("callstack_instr:  setting up threaded stack_type\n");
    panda_require("osi");
    assert(init_osi_api());
    // the API needed is in the 'core' OSI plugin - no need to call out OS
    // specific deriviation
    return true;
#else
    fprintf(stderr, "ERROR:  threaded stack_type is only supported on x86 (32-bit)\n");
    return false;
#endif
}


bool init_plugin(void *self) {

    // get arguments to this plugin
    panda_arg_list *args = panda_get_args("callstack_instr");
    verbose = panda_parse_bool_opt(args, "verbose", "enable verbose output");

    // they really, really want the default stack_type to be threaded if an
    // os is provided
    const char *stackType;
    if (OS_UNKNOWN == panda_os_familyno) {
        stackType = panda_parse_string_opt(args, "stack_type", "asid",
                "type of segregation used for stack entries (threaded, heuristic, or asid");
    } else {
        stackType = panda_parse_string_opt(args, "stack_type", "threaded",
                "type of segregation used for stack entries (threaded, heuristic, or asid");
    }
    if (0 == strcmp(stackType, "asid")) {
        stack_segregation = STACK_ASID;
    } else if (0 == strcmp(stackType, "heuristic")) {
        stack_segregation = STACK_HEURISTIC;
    } else if (0 == strcmp(stackType, "threaded")) {
        stack_segregation = STACK_THREADED;
    } else {
        printf("ERROR:  callstack_instr:  invalid stack_type (%s) provided\n",
                stackType);
        return false;
    }

#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    bool setup_ok = true;

    // the STACK_THREADED stack type needs some OS specific setup
    if (STACK_THREADED == stack_segregation) {
        if (OS_UNKNOWN == panda_os_familyno) {
            printf("WARNING:  callstack_instr: no OS specified, switching to asid stack_type\n");
            stack_segregation = STACK_ASID;
        } else {
            setup_ok = setup_osi();
        }
    } else if (STACK_ASID == stack_segregation) {
        printf("callstack_instr:  using asid stack_type\n");
    } else {
        printf("callstack_instr:  using heuristic stack_type\n");
    }

    return setup_ok;
}

void uninit_plugin(void *self) {
    // nothing to do
}

/* vim: set tabstop=4 softtabstop=4 expandtab ft=cpp: */

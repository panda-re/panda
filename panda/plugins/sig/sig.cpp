/* PANDABEGINCOMMENT
 *
 *  Authors:
 *  Tiemoko Ballo           N/A
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <set>
#include <map>
#include <string>
#include <vector>

#include "panda/plugin.h"
#include "panda/common.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi_linux/osi_linux_ext.h"

#include "sig.h"
#include "sig_int_fns.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
}

// Globals -------------------------------------------------------------------------------------------------------------

std::vector<sig_event_t> hyper_sig_events;
std::set<int32_t> hyper_blocked_sigs;
std::map<std::string, std::set<int32_t>> hyper_blocked_sigs_by_proc;

// Python CFFI API -----------------------------------------------------------------------------------------------------

// Block a signal for all processes
void block_sig(int32_t sig) {
    hyper_blocked_sigs.insert(sig);
}

// Block a signal only for a named process
void block_sig_by_proc(int32_t sig, char* proc_name) {

    std::string name(proc_name);
    auto named_block = hyper_blocked_sigs_by_proc.find(name);

    if (named_block == hyper_blocked_sigs_by_proc.end()) {
        std::set<int32_t> new_sig_set{sig};
        hyper_blocked_sigs_by_proc.insert(std::make_pair(proc_name, new_sig_set));
    } else {
        named_block->second.insert(sig);
    }
}

// Core ----------------------------------------------------------------------------------------------------------------

// Per Luke C., we'll supress by swapping to SIGWINCH instead of re-directing control flow from the hypervisor
bool supress_curr_sig(CPUState* cpu) {

    target_ulong sigwinch_num = 28;

    #if defined(TARGET_I386)
        // int 0x80 -> ecx
        // https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux#int_0x80
        #define SIG_ARG_REG &(((CPUArchState*)cpu->env_ptr)->regs[1])
    #elif defined(TARGET_X86_64)
        // syscall -> rsi
        // https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux#syscall
        #define SIG_ARG_REG &(((CPUArchState*)cpu->env_ptr)->regs[6])
    #elif defined(TARGET_ARM)
        // swi -> r1
        // https://jumpnowtek.com/shellcode/linux-arm-shellcode-part1.html
        #define SIG_ARG_REG &(((CPUArchState*)cpu->env_ptr)->regs[1])
    #elif defined(TARGET_AARCH64)
        // swi -> x1
        // https://jumpnowtek.com/shellcode/linux-arm-shellcode-part1.html
        #define SIG_ARG_REG &(((CPUArchState*)cpu->env_ptr)->xregs[1])
    #elif defined(TARGET_MIPS)
        // a1
        #define SIG_ARG_REG &(((CPUArchState*)cpu->env_ptr)->active_tc.gpr[5])
    #else
        // NOP for unsupported architectures
        #define SIG_ARG_REG &sigwinch_num
    #endif

    *SIG_ARG_REG = sigwinch_num;
    return true;
}

void sig_mitm(CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig) {

    bool suppressed = false;

    // pid -> signal destination process name
    std::string dst_proc_name("UNKOWN_DST_PROC");
    GArray *proc_list = get_processes(cpu);
    if (proc_list != NULL) {
        for (int i = 0; i < proc_list->len; i++) {
            OsiProc *proc = &g_array_index(proc_list, OsiProc, i);
            if (proc->pid == pid) {
                dst_proc_name = proc->name;
                break;
            }
        }
    }

    // Optional supression
    if (hyper_blocked_sigs.find(sig) != hyper_blocked_sigs.end()) {
        suppressed = supress_curr_sig(cpu);
    } else {
        auto named_block = hyper_blocked_sigs_by_proc.find(dst_proc_name);
        if (named_block != hyper_blocked_sigs_by_proc.end()) {
            if (named_block->second.find(sig) != named_block->second.end()) {
                suppressed = supress_curr_sig(cpu);
            }
        }
    }

    // Logging
    OsiProc* curr_proc = get_current_process(cpu);
    sig_event_t sig_event = {
        sig,
        suppressed,
        curr_proc->name,
        dst_proc_name,
        curr_proc->pid,
        pid,
    };
    hyper_sig_events.push_back(sig_event);
}

// Setup/Teardown ------------------------------------------------------------------------------------------------------

bool init_plugin(void *_self) {

    // Setup dependencies
    panda_enable_precise_pc();
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    panda_require("osi");
    assert(init_osi_api());
    panda_require("osi_linux");
    assert(init_osi_linux_api());

    // Setup signature
    switch (panda_os_familyno) {
       case OS_LINUX: {
            //#if (defined(TARGET_I386) || defined(TARGET_ARM) || defined(TARGET_MIPS))
            #if (defined(TARGET_I386) || defined(TARGET_ARM))
                printf("sig: setting up 32-bit Linux.\n");
                PPP_REG_CB("syscalls2", on_sys_kill_enter, sig_mitm);
            #elif (defined(TARGET_X86_64) || defined(TARGET_AARCH64))
                printf("sig: setting up 64-bit Linux.\n");
                PPP_REG_CB("syscalls2", on_sys_kill_enter, sig_mitm);
            #else
                fprintf(stderr, "sig: [ERROR] Unsuppported architecture!\n");
                return false;
            #endif
            return true;
        } break;
        default: {
            fprintf(stderr, "sig: [ERROR] Unsuppported operating system!\n");
            return false;
        }
    }
}

void uninit_plugin(void *self) {
    // TODO: flush events to panda log here
}
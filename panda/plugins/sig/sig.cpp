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

std::set<int32_t> hyper_blocked_sigs;       // Ordered set -> O(1) lookup
std::vector<sig_event_t> hyper_sig_events;  // Buffer before write to PANDA LOG

// API -----------------------------------------------------------------------------------------------------------------

void block_sig(int32_t sig) {
    hyper_blocked_sigs.insert(sig);
}

// Core ----------------------------------------------------------------------------------------------------------------

bool supress_curr_sig(CPUState* cpu) {
    // TODO: arch-specific signal supression logic here
    return true;
}

void sig_mitm(CPUState* cpu, target_ulong pc, int32_t pid, int32_t sig) {

    bool suppressed = false;

    // Optional supression
    if (hyper_blocked_sigs.find(sig) != hyper_blocked_sigs.end()) {
        suppressed = supress_curr_sig(cpu);
    }

    // Logging
    OsiProc* curr_proc = get_current_process(cpu);
    sig_event_t sig_event = {
        sig,
        suppressed,
        curr_proc->name,
        "UNKOWN_DST_PROC", //TODO: how to get actual dest name from pid?
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

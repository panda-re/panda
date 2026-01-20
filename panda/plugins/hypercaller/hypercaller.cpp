/* PANDABEGINCOMMENT
 * 
 * Authors:
 * Luke Craig luke.craig@ll.mit.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include <unordered_map>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
bool hypercall(CPUState *cpu);
#include "hypercaller.h"
}
bool debug = false;
#define dprintf(...) if (debug) { printf(__VA_ARGS__); fflush(stdout); }

std::unordered_map<target_ulong, hypercall_t> hypercalls;

void register_hypercall(uint32_t magic, hypercall_t hyp) {
    if (hypercalls.find(magic) == hypercalls.end()) {
        hypercalls[magic] = hyp;
        dprintf("[hypercaller] registered hypercall with magic 0x%x\n", magic);
    } else {
        dprintf("[hypercaller] Hypercall already registered with magic 0x%x\n", magic);
        assert(false);
    }
}

void unregister_hypercall(uint32_t magic) {
    dprintf("[hypercaller] unregistered hypercall with magic 0x%x\n", magic);
    hypercalls.erase(magic);
}

// Use syscall notation
uint32_t get_magic(CPUState *cpu) {
    uint32_t magic;
    CPUArchState * env = (CPUArchState *)cpu->env_ptr;

#if defined(TARGET_ARM)
    // r7
    magic = env->regs[7];
#if defined(TARGET_AARCH64)
    if (env->aarch64 != 0) {
        // XR
        magic = env->xregs[8];
    }
#endif
#elif defined(TARGET_MIPS)
    // V0
    magic = env->active_tc.gpr[2];
#elif defined(TARGET_I386)
    // eax
    magic = env->regs[R_EAX];
#elif defined(TARGET_PPC)
    // r0
    magic = env->gpr[0];
#else
    #error "Unsupported target architecture"
#endif
    return magic;
}

bool guest_hypercall(CPUState *cpu) {
    uint32_t magic = get_magic(cpu);
    dprintf("[hypercaller] recevied magic 0x%x\n", magic);
    dprintf("[hypercaller] registered hypercalls size %lx\n", hypercalls.size());
    if (hypercalls.find(magic) != hypercalls.end()) {
        dprintf("[hypercaller] attempt to call registered hypercall with magic 0x%x\n", magic);
        hypercalls[magic](cpu);
        dprintf("[hypercaller] attempt complete\n");
        return true;
    }
    return false;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .guest_hypercall = guest_hypercall };
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    dprintf("[hypercaller] init_plugin called\n");
    return true;
}

void uninit_plugin(void *self) {
    dprintf("[hypercaller] uninit_plugin called\n");
}
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
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}


#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h"

#include <map>

typedef void (*log_fn)(CPUState *cpu, target_ulong pc);
typedef std::map<target_ulong, log_fn> function_map;

void nop(CPUState *cpu, target_ulong pc){
    printf("i was called: %x\n", pc);
}

function_map logging_callbacks;


void on_call_shannon_cb(CPUState *cpu, target_ulong pc){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t r0 = env->regs[0];
    uint32_t r1 = env->regs[1];
    uint32_t r2 = env->regs[2];
    //printf("There was a call\n");
    if ( logging_callbacks.find(pc) != logging_callbacks.end() ) {
        logging_callbacks.at(pc)(cpu, pc);
    }

}






bool init_plugin(void *self) {
    //panda_cb pcb;


    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;

    PPP_REG_CB("callstack_instr", on_call, on_call_shannon_cb);

    logging_callbacks[0x4054f398] = nop; // log_fatal_error_file_line
    logging_callbacks[0x405489ae] = nop; // log_printf
    logging_callbacks[0x40c71964] = nop; // log_error_buf"
    logging_callbacks[0x4054d660] = nop; // log_format_buf
    logging_callbacks[0x40549130] = nop; // log_printf_debug
    logging_callbacks[0x40cb8f5c] = nop; // log_printf_stage


    printf("There was a call\n");

    return true;
}

void uninit_plugin(void *self) { }

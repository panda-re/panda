
#include "taint2/taint2.h"
#include "panda/plugin.h"
#include "taint2/taint2_ext.h"

extern "C" {

#include "panda/plugin_plugin.h"

bool init_plugin(void *);
void uninit_plugin(void *);

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"
}

void on_ret(CPUState *cpu, target_ulong func) {
    if (func < 0x10000000) {
        if (((CPUArchState*)cpu->env_ptr)->regs[0] == 0xffffffff) {
            printf ("rv is -1: applying taint labels fn = %x\n", func);
            for (int i=0; i<4; i++)
                taint2_label_reg(0, i, 1);
        }
    }
}

void init_taint(CPUState *cpu) {
    taint2_enable_taint();    
}


bool init_plugin(void *self) {

    panda_require("callstack_instr");
    panda_require("taint2");
    assert(init_taint2_api());

    panda_enable_precise_pc();
    panda_cb pcb = { .after_machine_init = init_taint };
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    return TRUE;
}

void uninit_plugin(void *) {
}

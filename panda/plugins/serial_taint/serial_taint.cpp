/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "taint2/taint2.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}

int serial_write(CPUState *cpu, uint64_t fifo_addr, uint32_t port_addr, uint8_t value)
{
    if (!taint2_enabled()) {
        // During a write, if taint hasn't been enabled we don't need to do anything.
        return 0;
    }

    // During a write, propagate taint from the port shadow to IO shadow.
    taint2_labelset_port_iter(port_addr, [](uint32_t label, void *fifo_addr) {
        taint2_label_io_additive(*(uint64_t *)fifo_addr, label);
        return 0;
    }, &fifo_addr);

    return 0;
}

int serial_send(CPUState *cpu, uint64_t fifo_addr, uint8_t value)
{
    if (!taint2_enabled()) {
        // During a send, if taint hasn't been enabled we don't need to do anything.
        return 0;
    }

    // During a send, now we report whether or not the byte going out the port is tainted.
    taint2_labelset_io_iter(fifo_addr, [](uint32_t label, void *pval) {
        uint8_t value = *(uint8_t *)pval;
        fprintf(stderr, "Tainted Serial TX (value=0x%X, label=0x%X)\n", value, label);
        return 0;
    }, &value);            

    return 0;
}

bool init_plugin(void *self)
{
    panda_require("taint2");
    assert(init_taint2_api());

    panda_cb pcb;

    pcb.replay_serial_write = serial_write;
    panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_WRITE, pcb);

    pcb.replay_serial_send = serial_send;
    panda_register_callback(self, PANDA_CB_REPLAY_SERIAL_SEND, pcb);

    return true;
}

void uninit_plugin(void *self) { }

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
void on_replay_net_transfer(CPUState *env, uint32_t type, uint64_t src_addr, uint64_t dst_addr, size_t num_bytes);
void on_replay_handle_packet(CPUState *env, uint8_t *buf, size_t size, uint8_t direction, uint64_t buf_addr_rec);
}

void on_replay_net_transfer(CPUState* env, uint32_t type, uint64_t src_addr,
                            uint64_t dst_addr, size_t num_bytes) {
    printf("net transfer: src: %" PRIx64 ", dst: %" PRIx64 ", n: %zu\n",
           src_addr, dst_addr, num_bytes);
    return;
}

void on_replay_handle_packet(CPUState *env, uint8_t *buf, size_t size,
                             uint8_t direction, uint64_t buf_addr_rec) {
    printf("handle packets: buf: %p, size: %zu, direction: %u, "
           "buf_addr_rec: %" PRIx64 "\n", buf, size, direction, buf_addr_rec);
        printf("start content: \n");
        for (int i = 0; i < size; i++) {
            printf("%c, ", buf[i]);
        }
        printf("\n end content \n");
    return;
}

bool init_plugin(void *self) {
    panda_cb pcb;
    pcb.replay_net_transfer = on_replay_net_transfer;
    panda_register_callback(self, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    pcb.replay_handle_packet = on_replay_handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);
    return true;
}

void uninit_plugin(void *self) { }

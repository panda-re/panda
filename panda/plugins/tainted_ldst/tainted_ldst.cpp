
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

#include <cstdio>

#include "panda/addr.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "taint2/label_set.h"
#include "taint2/taint2.h"

extern "C" {
#include <stdio.h>
#include "panda/rr/rr_log.h"
#include "panda/plog.h"
#include "taint2/taint2_ext.h"
}

// this includes on_ptr_load on_ptr_store
#include "taint2/taint2.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

#include <stdint.h>
}



#ifdef CONFIG_SOFTMMU


// a is addr of pointer. 
// size is how many bytes loaded or stored
void log_ldst(Addr a, uint64_t size, bool is_load) {
    // a is an llvm reg
    assert (a.typ == LADDR);
    // count number of tainted bytes on this reg
    uint32_t num_tainted = 0;
    Addr ao = a;
    for (uint32_t o=0; o<size; o++) {
        ao.off = o;
        num_tainted += (taint2_query(ao) != 0);
    }
    if (num_tainted > 0) {
        CPUState *cpu = first_cpu;
        target_ulong asid = panda_current_asid(cpu);
        Panda__TaintedLdst *tldst = (Panda__TaintedLdst *) malloc(sizeof(Panda__TaintedLdst));
        *tldst = PANDA__TAINTED_LDST__INIT;        
        tldst->n_taint_query = num_tainted;
        tldst->is_load = is_load;
        tldst->asid = asid;
        tldst->taint_query = (Panda__TaintQuery **) malloc (sizeof (Panda__TaintQuery *) * num_tainted);
        uint32_t i=0;
        for (uint32_t o=0; o<size; o++) {
            Addr ao = a;
            ao.off = o;
            if (taint2_query(ao)) {
                tldst->taint_query[i++] = taint2_query_pandalog(ao, o);
            }
        }
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.tainted_ldst = tldst;
        pandalog_write_entry(&ple);
        for (uint32_t i=0; i<num_tainted; i++) {
            pandalog_taint_query_free(tldst->taint_query[i]);
        }
        free(tldst);
    }
}


// a is addr of ptr. 
// srcdest is value of ptr for load/str -- not needed
void tainted_load(Addr a, uint64_t srcdst, uint64_t size) {
    log_ldst(a, size, /* is_load= */ true);
}


// a is addr of ptr. 
// srcdest is value of ptr for load/str -- not needed
void tainted_store(Addr a, uint64_t srcdst, uint64_t size) {
    log_ldst(a, size, /* is_load= */ false);
}


#endif

bool init_plugin(void *self) {
    panda_require("taint2");
    assert (init_taint2_api());    
    panda_enable_precise_pc();
    PPP_REG_CB("taint2", on_ptr_load, tainted_load);
    PPP_REG_CB("taint2", on_ptr_store, tainted_store);
    return true;
}


void uninit_plugin(void *self) {
}

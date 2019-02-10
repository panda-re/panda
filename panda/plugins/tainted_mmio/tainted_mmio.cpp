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
#include "taint2/taint2.h"

extern "C" {   
#include <assert.h>
#include "taint2/taint2_ext.h"
#include "panda/addr.h"
}

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <set>

/*
  This plugin's whole purpose in life is to apply taint labels to
  reads (loads) from unassigned memory regions.  The idea is to track
  taint for these and then employ other plugins such as tainted_branch
  to tell what that data coming from god-knows-what device is actually
  used to decide.
*/


using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

#ifdef CONFIG_SOFTMMU

bool only_label_uninitialized_reads = false;

// a taint label
typedef uint32_t Tlabel;

// map from taint label to mmio addr
map<Tlabel,uint64_t> label2ioaddr;
map<uint64_t,Tlabel> ioaddr2label;

uint64_t last_unassigned_io_read = 0;

bool taint_on = false;

void enable_taint(CPUState *env) {
    printf ("tainted_mmio plugin is enabling taint\n");
    taint2_enable_taint();
    taint_on = true;
}



/*
  We are assuming this callback will run *before* the label_io_read
  one.  Why?  Because this one involves actual emulation whereas the
  other one involves the corresponding taint computation, which
  happens, logically, after emulation.
*/
void saw_unassigned_io_read(CPUState *env, target_ulong pc, hwaddr addr, 
                            uint32_t size, uint64_t *val) {
    last_unassigned_io_read = addr;    
    cout << "Saw unassigned io read of " << hex << addr << dec << "\n";
}

// Apply taint labels to mmio
void label_io_read(Addr reg, uint64_t paddr, uint64_t size) {

    if (!taint_on) return;

    bool label_it = false;
    if (only_label_uninitialized_reads 
         && (paddr == last_unassigned_io_read)) {
        cout << "Unassigned mmio read of " << hex << paddr << dec << " \n";
        label_it = true;
    }
    if (!only_label_uninitialized_reads) {
        cout << "mmio read of " << hex << paddr << dec << " \n";
        label_it = true;
    }
    if (label_it) {
        assert (reg.typ == GREG);
        cout << "... load to register # " << reg.val.gr << "\n";
        cout << "... tainting register destination\n";
        Tlabel label;
        if (ioaddr2label.count(paddr) > 0) 
            label = ioaddr2label[paddr];
        else {
            label = label2ioaddr.size() + 1;
            label2ioaddr[label] = paddr;
            ioaddr2label[paddr] = label;
            cout << "New taint label label " << label << " for io addr " << hex << paddr << "\n";
        }
        for (int i=0; i<size; i++) {
            taint2_label_reg(reg.val.gr, i, label);
        }
    }    
}

#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU
    panda_require("taint2");
    assert(init_taint2_api());

    panda_arg_list *args = panda_get_args("tainted_mmio");
    only_label_uninitialized_reads = panda_parse_bool_opt(args, "uninit", "if set this means we will only label reads from uninitialized mmio regions");

    panda_cb pcb;
    pcb.after_machine_init = enable_taint;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);
    
    if (only_label_uninitialized_reads) {
        cout << "tainted_mmio: only labeling uninitialized mmio reads\n";
        pcb.unassigned_io_read = saw_unassigned_io_read;
        panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    }
    else
        cout << "tainted_mmio: labeling all mmio reads\n";

    PPP_REG_CB("taint2", on_after_load, label_io_read);
    return true;
#else
    return false;
#endif


}

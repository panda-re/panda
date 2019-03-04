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
#include "panda/plog.h"
}

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <set>

/*
  Tainted MMIO labeling.

  This plugin's whole purpose in life is to apply taint labels to
  reads (loads) from memory-mapped io regions.  The idea is use this
  to track taint for these and then employ other plugins such as
  tainted_branch to tell when/where that mmio data is being used to
  decide something.

  How does all this work?  Its a bit Rube Goldberg...
  
  If we have called panda_enable_memcb(), then we have access to
  callbacks that run in helper_le_ldY_XXX_panda, before and after the
  call to helper_le_ldY_XXX.  Great.

  We also have a callback in unassigned_mem_read which runs whenever
  there is a read attempted from an unassigned IO region. Excellent.

  Now the not so great.

  Recall that the way the taint system works, its operation is
  interleaved with emulation.  More precisely, we have code that
  emulates a single guest instruction then code that updates the taint
  system appropriately, then code that emulates the next instruction,
  then more taint system updates for that instruction,
  etc. Unfortunately, this means that these seemingly useful callbacks
  (before & after load, as well as the unassigned mem io read one) all
  run BEFORE the corresponding operations take place to update the
  taint state.  Even the _after_ one...  This means if we were to try
  to label a read using the PANDA_CB_VIRT_MEM_AFTER_READ, that label
  would be immediately wiped out, by the subsequent interleaved
  taint system update.  Ugh.

  We do have callbacks embedded in the taint system, however.  One of
  these, on_after_load, runs just after the taint has been transferred
  via a load instruction and gives one access to what register the
  load went to. 

  A little more background. Here's how the call chain works for when
  there is a memory mapped io read.

  softmmu_template.h:
    a: helper_le_ldY_XXX_panda
    b: helper_le_ldY_XXX
    c: io_read
  
  cputlb.c:
    d: io_readx

  memory.c:
    e: memory_region_dispatch_read
    f: unassigned_mem_read
    
   The call chain is
   a -> b -> c -> d -> e -> f 

   So that entire chain takes place when there is a load.  THEN we
   update taint accordingly.
  
   Here's how the Rube Goldberg machine works that is this plugin.
   We end up using three of those callback locations.

   1. We unset a flag, is_unassigned_io, in fn before_virt_read,
   registered with PANDA_CB_VIRT_MEM_BEFORE_READ, effectively in a.

   2. We the set that flag if we ever end up in f, in
   saw_unassigned_io_read, which is registered with
   PANDA_CB_UNASSIGNED_IO_READ.

   3. Finally, we register label_io_read to run at on_after_load.
   That callback checks if the value is_unassigned_io is true, which
   means that immediately previous memory read was from unassigned io.
   This means we can apply taint labels to the register into which the
   read went.

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

bool taint_on = false;
bool is_unassigned_io;
target_ulong virt_addr;


void enable_taint(CPUState *env) {
    printf ("tainted_mmio plugin is enabling taint\n");
    taint2_enable_taint();
    taint_on = true;
    assert (pandalog);
}


int before_virt_read(CPUState *env, target_ulong pc, target_ulong addr,
                     target_ulong size) {    
    // clear this before every read
    is_unassigned_io = false;    
    virt_addr = addr;
    return 1;
}


hwaddr unassigned_read_addr;

void saw_unassigned_io_read(CPUState *env, target_ulong pc, hwaddr addr, 
                            uint32_t size, uint64_t *val) {
    cerr << "tainted_mmio: pc=" << hex << panda_current_pc(env) 
         << ": Saw unassigned io read virt_addr=" 
         << virt_addr << " addr=" << addr << dec << "\n";
    is_unassigned_io = true;
    unassigned_read_addr = addr;
}


// Apply taint labels to mmio
void label_io_read(Addr reg, uint64_t paddr, uint64_t size) {

    if (!is_unassigned_io) return;

    cerr << "label_io_read: pc=" << hex << panda_current_pc(first_cpu) 
         << ": addr=" << unassigned_read_addr << dec << "\n";

    if (!taint_on) return;

    bool label_it = false;
    if (only_label_uninitialized_reads) {
        cerr << "Unassigned mmio read of " << hex << unassigned_read_addr << dec << " \n";
        label_it = true;
    }
    if (!only_label_uninitialized_reads) {
        cerr << "mmio read of " << hex << unassigned_read_addr << dec << " \n";
        label_it = true;
    }
    if (label_it) {
        cerr << "... tainting register destination\n";
        Tlabel label;
        if (ioaddr2label.count(unassigned_read_addr) > 0) 
            label = ioaddr2label[unassigned_read_addr];
        else {
            label = label2ioaddr.size() + 1;
            label2ioaddr[label] = unassigned_read_addr;
            ioaddr2label[unassigned_read_addr] = label;
            Panda__TaintedMmioLabel *tml = (Panda__TaintedMmioLabel*) malloc(sizeof(Panda__TaintedMmioLabel));
            *tml = PANDA__TAINTED_MMIO_LABEL__INIT;
            tml->pc = panda_current_pc(first_cpu);
            tml->label = label;
            tml->addr = unassigned_read_addr;
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.tainted_mmio_label = tml;
            pandalog_write_entry(&ple);
            free(tml);
        }
        cerr << "Taint label=" << label << " for io addr=" 
             << hex << unassigned_read_addr << " size=" << dec << size << "\n";
        for (int i=0; i<size; i++) {           
            taint2_label_addr(reg, i, label);
        }
    }    
}

#endif

bool init_plugin(void *self) {

#ifdef CONFIG_SOFTMMU

    // taint2 must be on
    panda_require("taint2");
    // and we need its api
    assert(init_taint2_api());    

    // this make sure we know, in the taint system, the pc for every instruction
    panda_enable_precise_pc();
    // enables the before/after virt mem read / write callbacks
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("tainted_mmio");
    only_label_uninitialized_reads = panda_parse_bool_opt(args, "uninit", "if set this means we will only label reads from uninitialized mmio regions");

    panda_cb pcb;
    pcb.after_machine_init = enable_taint;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    pcb.virt_mem_before_read = before_virt_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
    
    if (only_label_uninitialized_reads) {
        cerr << "tainted_mmio: only labeling uninitialized mmio reads\n";
        pcb.unassigned_io_read = saw_unassigned_io_read;
        panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    }
    else
        cerr << "tainted_mmio: labeling all mmio reads\n";

    PPP_REG_CB("taint2", on_after_load, label_io_read);
    return true;
#else
    return false;
#endif


}


void uninit_plugin(void *self) {
    
    
}


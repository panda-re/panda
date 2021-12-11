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
#include "taint2/addr.h"

extern "C" {
#include <assert.h>
#include "taint2/taint2_ext.h"
#include "panda/plog.h"
}

#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>

/*
  Tainted MMIO labeling.

  This plugin's whole purpose in life is to apply taint labels to
  reads (loads) from memory-mapped io regions.  The idea is to use this
  to track taint for these and then employ other plugins such as
  tainted_branch to tell when/where that mmio data is being used to
  decide something.

  How does all this work?  It's a bit Rube Goldberg...

  If we have called panda_enable_memcb(), then we have access to
  callbacks that run in virtual memory load fns:
  helper_le_ldY_XXX_panda, before and after the
  call to helper_le_ldY_XXX.  Great.

  We also have a callback in unassigned_mem_read which runs whenever
  there is a read attempted from an unassigned IO region. Excellent.

  Now the not so great.

  Recall that, the way the taint system works, its operation is
  interleaved with emulation.  More precisely, we have code that
  emulates a single guest instruction then code that updates the taint
  system appropriately, then code that emulates the next instruction,
  then more taint system updates for that instruction,
  etc. Unfortunately, this means that these seemingly useful callbacks
  (before & after load, as well as the unassigned mem io read one) all
  run BEFORE the corresponding operations take place to update the
  taint state.  Even the _after_ ones...  This means if we were to try
  to label a read using the PANDA_CB_VIRT_MEM_AFTER_READ, that label
  would be immediately wiped out, by the subsequent interleaved taint
  system update.  Ugh.

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

   So that entire chain, a -> .. -> f takes place when there is a
   load.  THEN we update taint accordingly.

   Here's how the Rube Goldberg machine works that is this plugin.
   We end up using three of those callbacks to achieve our purpose.

   1. We unset a flag, is_unassigned_io, in fn before_virt_read,
   registered with PANDA_CB_VIRT_MEM_BEFORE_READ. This is happening,
   effectively, in "a".

   2. We set that flag if we ever end up in "f".  We do this in
   saw_unassigned_io_read, which is registered with
   PANDA_CB_UNASSIGNED_IO_READ.

   3. Finally, we register label_io_read to run at on_after_load.
   That callback checks if the value is_unassigned_io is true, which
   means that the memory read that just happened was from unassigned io.
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

bool only_label_uninitialized_reads = true;

// a taint label
typedef uint32_t Tlabel;

// map from taint label to mmio addr
map<Tlabel,uint64_t> label2ioaddr;
map<uint64_t,Tlabel> ioaddr2label;

bool taint_on = false;
bool is_unassigned_io;
bool is_mmio;
size_t mmio_size;
uint64_t value;
target_ulong virt_addr;

uint64_t first_instruction;

target_ulong last_virt_read_pc;

uint64_t get_number(string line, string key, bool hex) {
    int index = line.find(key);
    int result = 0;
    if (index >= 0 && index <= line.length()) {
        index += key.size();
        index += 2;
        while (line[index] != ',' && line[index] != ' ' && index < line.length()) {
            result *= hex ? 16 : 10;
            if (line[index] >= 'a' && line[index] <= 'f') {
                result += 10;
                result += line[index] -'a';
            }
            else {
                result += line[index] - '0';
            }
            index ++;
        }
    }
    return result;
}

void enable_taint(CPUState *env, target_ulong pc) {
    if (!taint_on
        && rr_get_guest_instr_count() > first_instruction) {
        cerr << "tainted_mmio plugin is enabling taint\n";
        taint2_enable_taint();
        taint_on = true;
    }
    return;
}


target_ulong bvr_pc;

void before_virt_read(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                     size_t size) {
    // clear this before every read
    is_unassigned_io = false;
    is_mmio = false;
    virt_addr = addr;
    bvr_pc = panda_current_pc(first_cpu);

    return;
}

void before_phys_read(CPUState *env, target_ptr_t pc, target_ptr_t addr,
                          size_t size) {
    // Check if last read of taint memory is not handled
    if (!taint_on) return;

    for (int i = 0; i < size; i++) {
        if (taint2_query_ram(addr)) {
            last_virt_read_pc = panda_current_pc(first_cpu);
            break;
        }
    }
}


hwaddr read_addr;
target_ulong suior_pc;

bool saw_unassigned_io_read(CPUState *env, target_ulong pc, hwaddr addr,
                            size_t size, uint64_t *val) {
    // cerr << "tainted_mmio: pc=" << hex << panda_current_pc(first_cpu)
    //      << ": Saw unassigned io read virt_addr="
    //      << virt_addr << " addr=" << addr << dec << "\n";
    is_unassigned_io = true;
    mmio_size = size;
    read_addr = addr;
    suior_pc = panda_current_pc(first_cpu);

/*
    if (virt_addr == read_addr || bvr_pc == suior_pc) {
        cerr << "virt_addr =            " << hex << virt_addr << "\n";
        cerr << "read_addr = " << read_addr << "\n";
        cerr << "bvr_pc               = " << bvr_pc << "\n";
        cerr << "suior_pc             = " << suior_pc << "\n";
    }
*/
//  assert (virt_addr == read_addr);
    assert (bvr_pc == suior_pc);
    return false;
}

void saw_mmio_read(CPUState *env, target_ptr_t physaddr, target_ptr_t vaddr,
                            size_t size, uint64_t *val) {
    // cerr << "tainted_mmio: pc=" << hex << panda_current_pc(first_cpu)
    //      << ": Saw mmio read virt_addr="
    //      << vaddr << " addr=" << physaddr << dec << "\n";
    is_mmio = true;
    mmio_size = size;
    read_addr = physaddr;
    value = *val;
    suior_pc = panda_current_pc(first_cpu);
}


extern uint64_t last_input_index;

void label_io_read(Addr reg, uint64_t paddr, uint64_t size) {

    // yes we need to use a different one here than above
    target_ulong pc = panda_current_pc(first_cpu);

    if (!(pc == bvr_pc && pc == suior_pc))
        return;

    // cerr << "pc = " << hex << pc << "\n";
    // cerr << "bvr_pc = " << hex << bvr_pc << "\n";
    // cerr << "suior_pc = " << hex << suior_pc << "\n";
    // cerr << "paddr = " << hex << paddr << "\n";

//    if (pc != unassigned_io_read_pc) return;

    if (!is_unassigned_io && !is_mmio) return;


    // cerr << "label_io_read: pc=" << hex << panda_current_pc(first_cpu)
    //      << " instr=" << rr_get_guest_instr_count()
    //      << " : addr=" << read_addr << dec << "\n";

    if (!taint_on) return;

    bool label_it = false;
    if (only_label_uninitialized_reads) {
        cerr << "Unassigned mmio read of " << hex << read_addr << dec << " \n";
        label_it = true;
    }
    if (!only_label_uninitialized_reads) {
        cerr << "mmio read " << hex << read_addr << " rets " << value << dec << " \n";
        label_it = true;
    }
    if (label_it) {
        if (!execute_llvm)
            panda_enable_llvm();
        cerr << "... tainting register destination\n";
        Tlabel label;
        if (ioaddr2label.count(read_addr) > 0)
            // existing label
            label = ioaddr2label[read_addr];
        else {
            // new label
            label = label2ioaddr.size() + 1;
            label2ioaddr[label] = read_addr;
            ioaddr2label[read_addr] = label;
            Panda__TaintedMmioLabel *tml = (Panda__TaintedMmioLabel*) malloc(sizeof(Panda__TaintedMmioLabel));
            *tml = PANDA__TAINTED_MMIO_LABEL__INIT;
            tml->pc = panda_current_pc(first_cpu);;
            tml->label = label;
            tml->addr = read_addr;
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.tainted_mmio_label = tml;
            pandalog_write_entry(&ple);
            free(tml);
        }
        cerr << "Taint label=" << label << " for io addr="
             << hex << read_addr << " size=" << dec << size << "\n";
        reg.off = 0;

        assert (reg.typ == LADDR);
        cerr << "label_io Laddr[" << reg.val.la << "]\n";
        cerr << "symbolic_label[" << hex << last_input_index << dec << ":" << mmio_size << "]\n";
        for (int i=0; i<mmio_size; i++) {
            taint2_label_addr(reg, i, label);
            taint2_sym_label_addr(reg, i, last_input_index+i);
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

    // this makes sure we know, in the taint system, the pc for every instruction
    panda_enable_precise_pc();

    // enables the before/after virt mem read / write callbacks
    panda_enable_memcb();

    panda_arg_list *args = panda_get_args("tainted_mmio");
    only_label_uninitialized_reads = panda_parse_bool_opt(args, "uninit", "if set this means we will only label reads from uninitialized mmio regions");

	// enable taint at this instruction
    first_instruction = panda_parse_uint64(args, "first_instruction", 0);

    panda_cb pcb;
    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    pcb.virt_mem_before_read = before_virt_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);

    pcb.phys_mem_before_read = before_phys_read;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

    if (only_label_uninitialized_reads) {
        cerr << "tainted_mmio: only labeling uninitialized mmio reads\n";
        pcb.unassigned_io_read = saw_unassigned_io_read;
        panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    }
    else {
        cerr << "tainted_mmio: labeling all mmio reads\n";
        pcb.mmio_after_read = saw_mmio_read;
        panda_register_callback(self, PANDA_CB_MMIO_AFTER_READ, pcb);
    }

    PPP_REG_CB("taint2", on_after_load, label_io_read);
    return true;
#else
    return false;
#endif


}


void uninit_plugin(void *self) {


}


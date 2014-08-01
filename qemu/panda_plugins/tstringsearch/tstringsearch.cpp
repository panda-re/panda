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

extern "C" {

#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "../taint/taint_processor.h"
#include "../taint/taint_ext.h"

#include "../stringsearch/stringsearch.h"
#include "panda_plugin_plugin.h"


}


//#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
//#include <map>
//#include <fstream>
//#include <sstream>
//#include <string>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#ifdef CONFIG_SOFTMMU

bool tstringsearch_label_on = true;
bool first_match = true;

target_ulong the_pc;
target_ulong the_buf;
int the_len; 
uint32_t old_amt_ram_tainted;


void tstringsearch_label(uint64_t pc, uint64_t phys_addr) {
  if (tstringsearch_label_on == false) {
    return;
  }
  if (pc == the_pc) {
    printf ("\n****************************************************************************\n");
    printf ("applying taint labels to search string of length %d  @ p=0x" TARGET_FMT_lx "\n", the_len, the_buf);
    printf ("******************************************************************************\n");
    // label that buffer 
    int i;
    for (i=0; i<the_len; i++) {
      target_ulong va = the_buf + i;
      target_phys_addr_t pa = cpu_get_phys_addr(cpu_single_env, va);
      taint_label_ram(pa, i);
    }
    tstringsearch_label_on = false;
  }
}

 

void tstringsearch_match(CPUState *env, target_ulong pc, target_ulong addr,
			uint8_t *matched_string, uint32_t matched_string_length, 
			bool is_write) {

  // determine if the search string is sitting in memory, starting at addr - (strlen-1)
  // first, grab that string out of memory
  target_ulong p = addr - (matched_string_length-1);
  uint8_t thestring[MAX_STRLEN];
  panda_virtual_memory_rw(env, p, thestring, matched_string_length, 0);
  // now compare it to the search string
  printf ("thestring = [%s]\n", thestring);
  // NOTE: this is a write, so the final byte of the string hasn't yet been
  // written to memory since write callback is at start of fn.
  // thus, the matched_string_length - 1.
  // yes, we can get this right, but eh.
  if ((strncmp((char *)thestring, (char *)matched_string, matched_string_length-1)) == 0) {
    printf ("search string is sitting in memory starting at 0x%lx\n", (long unsigned int) p);
    
    // ok this is ugly.  save pc, buffer addr and len
    the_pc = pc;
    the_buf = p;
    the_len = matched_string_length;
    // this should enable
    tstringsearch_label_on = true;
    
    if (first_match) {
      first_match = false;
      // turn on taint.
      taint_enable_taint();
      // add a callback for taint processor st
      PPP_REG_CB("taint", on_load, tstringsearch_label);
      PPP_REG_CB("taint", on_store, tstringsearch_label);
    }
  
  }
}

#endif

bool init_plugin(void *self) {
  printf ("Initializing tstringsearch\n");

#ifdef CONFIG_SOFTMMU
  // this sets up the taint api fn ptrs so we have access
  bool x = init_taint_api();  
  assert (x==true);

  // register the tstringsearch_match fn to be called at the on_ssm site within panda_stringsearch
  PPP_REG_CB("stringsearch", on_ssm, tstringsearch_match) ;

  return true;
#else
  fprintf(stderr, "tstringsearch: plugin does not support linux-user mode\n");
  return false;
#endif
}


void uninit_plugin(void *self) {
}

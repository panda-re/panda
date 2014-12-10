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

/*

  This plugin runs with no arguments and is very simple. 
  It collects the set of asids (cr3 on x86) that are ever observed during
  a replay (checking just before each bb executes).  For each asid,
  the plugin, further, keeps track of the first instruction at which it
  is observed, and also the last.  Together, these two tell us for
  what fraction of the replay an asid (and thus the associated process)
  existed.  Upon exit, this plugin dumps this data out to a file 
  "asidstory" but also displays it in an asciiart graph.  

 */


// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <algorithm>
#include <map>
#include <cstdint>

#include "panda_common.h"


extern "C" {

    /*
#include <math.h>
#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h" 
#include "monitor.h"
#include "cpu.h"
    */

#include "panda_plugin.h"

    
    //#include "../bir/bir_ext.h"
#include "rr_log.h"
#include "rr_log_all.h"  
#include "panda_plugin_plugin.h"
    
    bool init_plugin(void *);
    void uninit_plugin(void *);

}


std::map < uint64_t, uint64_t > asid_first_instr;
std::map < uint64_t, uint64_t > asid_last_instr;

int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t asid = panda_current_asid(env);
    
    if (asid_first_instr.count(asid) == 0) {
        // new asid -- write down rr instruction count
        asid_first_instr[asid] = rr_get_guest_instr_count();
    }
    else {
        // old asid -- update last seen
        asid_last_instr[asid] =  rr_get_guest_instr_count();
    }
    return 0;
}




bool init_plugin(void *self) {    
#ifdef CONFIG_SOFTMMU    

    panda_cb pcb;
    pcb.before_block_exec = asidstory_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
#endif
    return false;
}



void uninit_plugin(void *self) {
    
    FILE *fp = fopen("asidstory", "w");
    bool first = true;
    uint64_t min_instr;
    uint64_t max_instr;
    
    for ( auto &kvp : asid_first_instr ) {
        uint64_t asid = kvp.first;
        uint64_t first_instr = kvp.second;
        uint64_t last_instr = asid_last_instr[asid];
        fprintf (fp, 
                 "%" PRIx64 
                 " %" PRIu64 
                 " %" PRIu64 
                 "\n", 
                 asid, first_instr, last_instr);
        if (first) {
            first = false;
            min_instr = first_instr;
            max_instr = last_instr;
        }
        else {
            min_instr = std::min(min_instr, first_instr);
            max_instr = std::max(max_instr, last_instr);
        }
    }
    fclose(fp);

    float m = 80.0 / (float) (max_instr - min_instr);
    for ( auto &kvp : asid_first_instr ) {
        uint64_t asid = kvp.first;
        uint64_t first_instr = kvp.second;
        uint64_t last_instr = asid_last_instr[asid];
        printf ( " %20" PRIx64 
                 " %15" PRIu64 
                 " %15" PRIu64
                 " : ",
                 asid, first_instr, last_instr);
        int fi = first_instr * m;
        int li = last_instr * m;
        if (fi == li) {
            li ++;
        }
        for (int i=0; i<fi; i++) {
            printf (" ");
        }
        for (int i=fi; i<li; i++) {
            printf ("#");
        }
        printf ("\n");
    }


}


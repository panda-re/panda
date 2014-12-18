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
  "asidstory" but also displays it in an asciiart graph.  At the bottom
  of the graph is a set of indicators you can use to choose a good
  rr instruction count for various purposes.

  Ok it now takes some parameters.
  vol_instr_count determines when volatility will get called on a 
  physical memory dump (which is written to "asidstory.vol.pmem", incidentally).
  vol_cmds is where you can put profile and volatility commands

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



bool vol_done = false;
uint64_t vol_instr_count = 0;
std::string vol_cmds = "";

std::map < uint64_t, uint64_t > asid_first_instr;
std::map < uint64_t, uint64_t > asid_last_instr;


// write physmem to a file
// and invoke volatility on it
void vol(char *outfilename) {
    printf ("vol %s\n", outfilename);
    std::string pmf = (std::string(outfilename)) + ".pmem";
    FILE *fp = fopen((char *) pmf.c_str(), "w");
    panda_memsavep(fp);
    fclose(fp);
    std::string cmd = "/usr/bin/volatility -f " + pmf + " " + vol_cmds; // " --profile=Linux_Debian_Wheezy_3_2_0-4-686-pae_x86 linux_pslist";
    fp = popen(cmd.c_str(), "r");
    FILE *fp2 = fopen(outfilename, "w");
    char line[4096];
    while (fgets(line, sizeof(line)-1, fp) != NULL) {
        fprintf(fp2, "%s", line);
    }
    fclose(fp2);
    printf ("...done\n");
}
 
    
#define MILLION 1000000


int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {
    uint64_t asid = panda_current_asid(env);

    if ((vol_instr_count != 0) 
        && (!vol_done) 
        && (rr_get_guest_instr_count() > vol_instr_count)) {
        printf ("instr count is %" PRIu64 " \n", rr_get_guest_instr_count());
        std::string fn = "asidstory.vol";
        vol((char *) fn.c_str());
        vol_done = true;
    }
    
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

    panda_arg_list *args = panda_get_args("asidstory");
    if (args != NULL) {
        int i;
        for (i = 0; i < args->nargs; i++) {
            if (0 == strncmp(args->list[i].key, "vol_instr_count", 15)) {
                vol_instr_count = atoll(args->list[i].value);
                printf ("vol_instr_count = %" PRIu64 " \n", vol_instr_count);
            }
            if (0 == strncmp(args->list[i].key, "vol_cmds", 8)) {
                vol_cmds = std::string(args->list[i].value);
                printf ("vol_cmds = %s\n", vol_cmds.c_str());
            }
        }
    }

    return true;
#endif
    return false;
}



void uninit_plugin(void *self) {
    
    FILE *fp = fopen("asidstory", "w");
    bool first = true;
    uint64_t min_instr=0;
    uint64_t max_instr=0;
    
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
    printf ("\n");
    for (int i=5; i<80; i+=5) {
        uint64_t instr = i / m;
        printf ("                      ");
        printf ("               ");
        printf (" %15" PRIu64 " : ", instr);
        for (int j=0; j<i; j++) {
            printf (" ");
        }
        printf ("^\n");
    }
        


}


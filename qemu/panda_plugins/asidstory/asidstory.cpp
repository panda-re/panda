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
#include <set>
#include <cstdint>



extern "C" {

#include "panda_plugin.h"
#include "panda_common.h"

#include "rr_log.h"
#include "rr_log_all.h"  
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"
#include "panda_plugin_plugin.h"
    
    bool init_plugin(void *);
    void uninit_plugin(void *);

}



uint32_t num_cells = 80;
uint64_t min_instr;
uint64_t max_instr = 0;
double scale;
bool vol_done = false;
uint64_t vol_instr_count = 0;
std::string vol_cmds = "";

std::map < uint64_t, std::set < uint32_t > > asid_instr;
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

uint64_t a_counter = 0;

std::map < uint64_t, std::map < std::string, uint32_t > > asid_to_name;


uint64_t asid_before = 0;
uint64_t first_instr = 0;
int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (max_instr == 0) {
        max_instr = replay_get_total_num_instructions();
        scale = ((double) num_cells) / ((double) max_instr); 
    }
    asid_before = panda_current_asid(env);
    first_instr = rr_get_guest_instr_count();
    if (asid_first_instr.count(asid_before) == 0) {
        // first time
        asid_first_instr[asid_before] = first_instr;
    }
    else {
        asid_first_instr[asid_before] = std::min(asid_first_instr[asid_before], first_instr);
    }
    return 0;
}




int asidstory_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *tb2) {
    uint64_t asid =  panda_current_asid(env);
    uint64_t last_instr = rr_get_guest_instr_count();
    if (asid_last_instr.count(asid) == 0) {
        // last time
        asid_last_instr[asid] = last_instr;
    }
    else {
        asid_last_instr[asid] = std::max(asid_last_instr[asid], last_instr);
    }
    // weird -- let's leave this one be
    if (asid_before != asid) {
        return 0;
    }
    a_counter ++;
    if ((a_counter%1000) == 0) {
        OsiProc *p = get_current_process(env);
        asid_to_name[asid][p->name] ++;
        a_counter ++;
    }
    if ((vol_instr_count != 0) 
        && (!vol_done) 
        && (rr_get_guest_instr_count() > vol_instr_count)) {
        printf ("instr count is %" PRIu64 " \n", rr_get_guest_instr_count());
        std::string fn = "asidstory.vol";
        vol((char *) fn.c_str());
        vol_done = true;
    }
        

    uint32_t cell = rr_get_guest_instr_count() * scale;
    asid_instr[asid].insert(cell);
    return 0;
}



    


bool init_plugin(void *self) {    

    printf ("Initializing plugin asidstory  XXX\n");

    // this sets up OS introspection API
    bool x = init_osi_api();  
    assert (x==true);
    
    panda_cb pcb;    
    pcb.before_block_exec = asidstory_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    pcb.after_block_exec = asidstory_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    
    panda_arg_list *args = panda_get_args("asidstory");
    vol_instr_count = panda_parse_uint64(args, "vol_instr_count", 0);
    vol_cmds = panda_parse_string(args, "vol_cmds", "xxx");
    
    min_instr = 0;
    

    return true;
}



void uninit_plugin(void *self) {
    
    FILE *fp = fopen("asidstory", "w");

    // write out concordance asid -> name
    for ( auto &kvp : asid_to_name ) {
        fprintf (fp, "0x%x : ", (unsigned int) kvp.first);
        for ( auto &kvp2 : asid_to_name[kvp.first] ) {
            fprintf (fp, "(%d, %s) ", kvp2.second, (const char *) kvp2.first.c_str());
        }
        fprintf (fp, "\n");
    }

    for ( auto &kvp : asid_instr ) {
        uint64_t asid = kvp.first;
        fprintf (fp, " %20" PRIx64 
                 " %15" PRIu64 
                 " %15" PRIu64
                 " : ",
                 asid, 
                 asid_first_instr[asid], asid_last_instr[asid]);
        for ( uint32_t i=0; i<num_cells; i++ ) {
            if ( asid_instr[asid].count(i) == 0 ) {
                fprintf (fp, " ");
            }
            else {
                fprintf (fp, "#");
            }
        }
        fprintf (fp, "\n");
    }
    fprintf (fp, "\n");
    for (uint32_t i=5; i<num_cells; i+=5) {
        uint64_t instr = i / scale;
        fprintf (fp, "                      ");
        fprintf (fp, "               ");
        fprintf (fp, " %15" PRIu64 " : ", instr);
        for (uint32_t j=0; j<i; j++) {
            fprintf (fp, " ");
        }
        fprintf (fp, "^\n");
    }
    fclose(fp);

        


}


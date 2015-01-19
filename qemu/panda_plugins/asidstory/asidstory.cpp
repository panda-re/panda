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


bool pid_ok(int pid) {
    if (pid < 4) {
        return false;
    }
    return true;
}


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
 
#define SAMPLE_CUTOFF 10    
#define SAMPLE_RATE 1
#define MILLION 1000000

uint64_t a_counter = 0;
uint64_t b_counter = 0;

typedef std::string Name;
typedef uint32_t Pid;
typedef uint64_t Asid;
typedef uint32_t Cell;
typedef uint64_t Count;
typedef uint64_t Instr;

std::map < Name, std::map < Pid, std::map < Cell, Count > > > namepid_cells;
std::map < Name, std::map < Pid, std::map < Asid, Count > > > namepid_to_asids;
std::map < Name, std::map < Pid, Instr > > namepid_first_instr;
std::map < Name, std::map < Pid, Instr > >  namepid_last_instr;

//char np[256];

void make_nps(Name &name, Pid pid, char *buf, uint32_t buf_len) {
    snprintf (buf, buf_len, "%d-%s", pid, (const char *) name.c_str());
}


int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {
    // NB: we only know max instr *after* replay has started,
    // so this code *cant* be run in init_plugin.  yuck.
    if (max_instr == 0) {
        max_instr = replay_get_total_num_instructions();
        scale = ((double) num_cells) / ((double) max_instr); 
    }

    a_counter ++;
    if ((a_counter % SAMPLE_RATE) != 0) {
        return 0;
    }
    OsiProc *p = get_current_process(env);
    if (pid_ok(p->pid)) {
        namepid_to_asids[p->name][p->pid][p->asid]++;
        // keep track of first rr instruction for each name/pid
        if ((namepid_first_instr.count(p->name) == 0) 
            || (namepid_first_instr[p->name].count(p->pid) == 0)) {
            namepid_first_instr[p->name][p->pid] = rr_get_guest_instr_count();
        }
    }
    return 0;
}





int asidstory_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *tb2) {
    OsiProc *p = get_current_process(env);

    b_counter ++;
    if ((b_counter % SAMPLE_RATE) != 0) {
        return 0;
    }
    if (pid_ok(p->pid)) {
        Instr instr = rr_get_guest_instr_count();
        namepid_to_asids[p->name][p->pid][p->asid]++;
        uint32_t cell = instr * scale;
        namepid_cells[p->name][p->pid][cell] ++;
        namepid_last_instr[p->name][p->pid] = std::max(namepid_last_instr[p->name][p->pid], instr);
    }
    if ((vol_instr_count != 0) 
        && (!vol_done) 
        && (rr_get_guest_instr_count() > vol_instr_count)) {
        printf ("instr count is %" PRIu64 " \n", rr_get_guest_instr_count());
        std::string fn = "asidstory.vol";
        vol((char *) fn.c_str());
        vol_done = true;
    }        
    return 0;
}



    


bool init_plugin(void *self) {    

    printf ("Initializing plugin asidstory\n");

    panda_require("osi");
   
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

    // write out concordance namepid to asid 
    std::map < Name, std::set < Pid > > namepid_ignore;
    for ( auto &kvp1 : namepid_to_asids ) {
        Name name = kvp1.first;
        for ( auto &kvp2 : kvp1.second ) {
            Pid pid = kvp2.first;
            uint64_t tc = 0;
            for ( auto &kvp3 : kvp2.second ) {
                //                Asid asid = kvp3.first;
                Count count = kvp3.second;
                tc += count;
            }
            // probably not a *real* process
            if (tc < SAMPLE_CUTOFF) {
                namepid_ignore[name].insert(pid);
                continue;
            }
            char nps[256];
            make_nps(name, pid, nps, 256);
            fprintf (fp, "%20s : ", nps);
            for ( auto &kvp3 : namepid_to_asids[name][pid] ) {
                Asid asid = kvp3.first;
                Count count = kvp3.second;            
                fprintf (fp, "(count=%d, asid=0x%x) ", (unsigned int) count, (unsigned int) asid);
            }            
            fprintf (fp, "\n");
        }
    }
    fprintf (fp, "\n");

    for ( auto &kvp1 : namepid_to_asids ) {
        Name name = kvp1.first;
        for ( auto &kvp2 : kvp1.second ) {
            Pid pid = kvp2.first;
            if ( namepid_ignore[name].count(pid) != 0) {
                continue;
            }
            char nps[256];
            make_nps(name, pid, nps, 256);
            fprintf (fp, "%20s : ", nps);            
            fprintf (fp, 
                     " %15" PRIu64 
                     " %15" PRIu64
                     " : ",                 
                     namepid_first_instr[name][pid], namepid_last_instr[name][pid]);
            for ( uint32_t i=0; i<num_cells; i++ ) {
                if ( namepid_cells[name][pid].count(i) == 0 ) {
                    fprintf (fp, " ");
                }
                else {
                    if ( namepid_cells[name][pid][i] < 2 ) {
                        fprintf(fp, " ");
                    }
                    else {
                        fprintf (fp, "#");
                    }
                }
            }        
            fprintf (fp, "\n");
        }
    }
    fprintf (fp, "\n");
    for (uint32_t i=5; i<num_cells; i+=5) {
        uint64_t instr = i / scale;
        fprintf (fp, "                      ");
        fprintf (fp, "                 ");
        fprintf (fp, " %15" PRIu64 " : ", instr);
        for (uint32_t j=0; j<i; j++) {
            fprintf (fp, " ");
        }
        fprintf (fp, "^\n");
    }
    fclose(fp);

}


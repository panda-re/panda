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

 */


// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <algorithm>
#include <map>
#include <set>
#include <cstdint>
#include <sstream>
#include <iomanip>

extern "C" {

#include "panda_plugin.h"
#include "panda_common.h"
#include "pandalog.h"

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

bool pid_ok(int pid) {
    if (pid < 4) {
        return false;
    }
    return true;
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

struct NamePid {
    Name name;
    Pid pid;
    Asid asid;

    NamePid(Name name, Pid pid, Asid asid) :
        name(name), pid(pid), asid(asid) {}

    bool operator<(const NamePid &rhs) const {
        return name < rhs.name || (name == rhs.name && pid < rhs.pid) ||
            (name == rhs.name && pid == rhs.pid && asid < rhs.asid);
    }
};

struct ProcessData {
    std::map<Cell, Count> cells;
    Count count;
    Instr first;
    Instr last;

    ProcessData() : count(0), first(0), last(0) {}
};

std::map<NamePid, ProcessData> process_datas;
typedef std::pair<NamePid, ProcessData> ProcessKV;

static unsigned digits(uint64_t num) {
    return num > 0 ? (int)(log10((double)num) + 1) : 1;
}

using std::hex;
using std::dec;
using std::setw;
using std::setfill;
using std::endl;
void spit_asidstory() {
    FILE *fp = fopen("asidstory", "w");

    for (auto &pd_kv : process_datas) {
        const NamePid &namepid = pd_kv.first;
        const ProcessData &pd = pd_kv.second;
        if (pd.count >= SAMPLE_CUTOFF) {
            std::stringstream ss;
            std::string shortname = namepid.name;
            if (shortname.compare(shortname.size() - 4, 4, ".exe") == 0) {
                shortname = shortname.substr(0, shortname.size() - 4); 
            }
            if (shortname.size() > 10) shortname = shortname.substr(0, 10);
            ss << setw(6) << namepid.pid << "  " <<
               setw(10) << shortname << " : " <<
               "(count=" << setw(digits(max_instr / SAMPLE_RATE)) << pd.count <<
               ", asid=0x" << setw(sizeof(target_ulong) * 2) <<
               hex << setfill('0') << namepid.asid << dec << setfill(' ') <<
               ") : " << setw(digits(max_instr)) << pd.first <<
               " -> " << setw(digits(max_instr)) << pd.last << endl;
            fprintf(fp, "%s", ss.str().c_str());
        }
    }

    fprintf(fp, "\n");

    std::vector<ProcessKV> sorted_pds(process_datas.begin(), process_datas.end());
    std::sort(sorted_pds.begin(), sorted_pds.end(),
            [](const ProcessKV &lhs, const ProcessKV &rhs) {
                return lhs.second.first < rhs.second.first; });

    for (auto &pd_kv : sorted_pds) {
        const NamePid &namepid = pd_kv.first;
        const ProcessData &pd = pd_kv.second;

        if (pd.count >= SAMPLE_CUTOFF) {
            std::stringstream ss;
            ss << namepid.pid << "-" << namepid.name;
            fprintf(fp, "%20s : [", ss.str().c_str());
            for (unsigned i = 0; i < num_cells; i++) {
                auto it = pd.cells.find(i);
                if (it == pd.cells.end() || it->second < 2) {
                    fprintf(fp, " ");
                } else {
                    fprintf(fp, "#");
                }
            }
            fprintf(fp, "]\n");
        }
    }

    fprintf(fp, "\n");
    for (uint32_t i=5; i<num_cells; i+=5) {
        uint64_t instr = i / scale;
        fprintf (fp, "%20" PRIu64 " :  ", instr);
        for (uint32_t j=0; j<i; j++) {
            fprintf (fp, " ");
        }
        fprintf (fp, "^\n");
    }
    fclose(fp);

}

char *last_name = 0;
target_ulong last_pid = 0;
target_ulong last_asid = 0;

int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if ((a_counter % 1000000) == 0) {
        spit_asidstory();
    }

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
        ProcessData &pd = process_datas[NamePid(p->name, p->pid, p->asid)];
        // keep track of first rr instruction for each name/pid
        if (pd.first == 0) {
            pd.first = rr_get_guest_instr_count();
        }
        if (pandalog) {
            if (last_name == 0
                || (p->asid != last_asid)
                || (p->pid != last_pid) 
                || (0 != strcmp(p->name, last_name))) {        
                Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                ple.has_asid = 1;
                ple.asid = p->asid;
                ple.has_process_id = 1;
                ple.process_id = p->pid;
                ple.process_name = p->name;
                pandalog_write_entry(&ple);           
                last_asid = p->asid;
                last_pid = p->pid;
                free(last_name);
                last_name = strdup(p->name);
            }
        }
    }
    free (p);
    return 0;
}

int asidstory_after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *tb2) {
    b_counter ++;
    if ((b_counter % SAMPLE_RATE) != 0) {
        return 0;
    }
    OsiProc *p = get_current_process(env);
    if (pid_ok(p->pid)) {
        Instr instr = rr_get_guest_instr_count();
        ProcessData &pd = process_datas[NamePid(p->name, p->pid, p->asid)];
        pd.count++;
        uint32_t cell = instr * scale;
        pd.cells[cell]++;
        pd.last = std::max(pd.last, instr);
    }
    free(p);
    return 0;
}

bool init_plugin(void *self) {    

    printf ("Initializing plugin asidstory\n");

    panda_require("osi");
   
    // this sets up OS introspection API
    assert(init_osi_api());

    panda_cb pcb;    
    pcb.before_block_exec = asidstory_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    pcb.after_block_exec = asidstory_after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    
    panda_arg_list *args = panda_get_args("asidstory");
    num_cells = panda_parse_ulong(args, "width", 100) - 25;
    
    min_instr = 0;   
    return true;
}

void uninit_plugin(void *self) {
  spit_asidstory();
}


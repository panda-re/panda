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
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cmath>

using std::hex;
using std::dec;
using std::setw;
using std::setfill;
using std::endl;

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

#include "panda/rr/rr_log.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "asidstory.h"


bool init_plugin(void *);
void uninit_plugin(void *);


// callback for when process changes
PPP_PROT_REG_CB(on_proc_change);

}

PPP_CB_BOILERPLATE(on_proc_change);

/*

Process info stability.  asidstory needs to know what process is at
each bb but that information as provided by Osi is unstable.

Here is a picture of what we observe happen wrt asid changing and
processes infor from Osi

*      |            |              |             |      !
sggggggbbbggggggggggbbbbbbbbbbbbbbbbbggggggggggggbbbggggg

s - start
g - we have a good proc (pid & name reasonable)
b - we have a bad proc (pid or name bad)

Where the '|' indicate an asid change.  

So here is how we handle that.  With a finite state machine.  At asid
change, we move to mode 'Process_unknown' which means are looking for
the first good process.  We also start in that mode.  We'll ask Osi
what the current process is at the beginning of each basic block until
we see a good one (pid and name make sense).  At which point, we'll
move to 'Process_suspicious' mode, which means we saw a good process
after asid change but we don't believe it yet.  If we see that same
process for PROCESS_GOOD_NUM basic blocks, then we believe it and move
to 'Process_known' mode.  If we observe a bad process (or just
different) whilst in the 'Process_suspicious' mode, we'll revert back to
'Process_unknown'.  We stay in 'Process_known' until asid changes which
moves us back into 'Process_unknown'.

*/

enum Mode {Process_unknown, Process_suspicious, Process_known};

Mode process_mode = Process_unknown;

#define PROCESS_GOOD_NUM 10

// use to count how many bb in a row have same proc name
// if that is changing we won't believe it
int process_counter=PROCESS_GOOD_NUM;

// used to control spit_asidstory printout frequency
bool *status_c=NULL;

// divide replay up into this many temporal cells
uint32_t num_cells = 80;
uint64_t min_instr;
uint64_t max_instr = 0;
double scale = 0;

bool debug = false;
 
#define MILLION 1000000
//#define NAMELEN 10
//#define NAMELENS "10"
#define NAMELEN 20
#define NAMELENS "20"

uint64_t a_counter = 0;
uint64_t b_counter = 0;


typedef std::string Name;
typedef uint32_t Pid;
typedef uint64_t Asid;
typedef uint32_t Cell;
typedef uint64_t Count;
typedef uint64_t Instr;
    
// if we see svchost more than once, e.g., we use this to append 1, 2, 3, etc to the name in our output
static std::map<std::string, unsigned> name_count;

//bool spit_out_total_instr_once = false;


bool proc_ok = false;
bool asid_just_changed = false;
OsiProc *first_good_proc = NULL;
uint64_t instr_first_good_proc;

target_ulong asid_at_asid_changed;

    
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
    std::string shortname;   
    std::map<Cell, Count> cells;  
    Count count;           
    Instr first;
    Instr last;

    ProcessData() : count(0), first(0), last(0) {}
};

std::map<NamePid, ProcessData> process_datas;
typedef std::pair<NamePid, ProcessData> ProcessKV;

static unsigned digits(uint64_t num) {
    return std::to_string(num).size();
}

void spit_asidstory() {
    FILE *fp = fopen("asidstory", "w");

    std::vector<ProcessKV> count_sorted_pds(process_datas.begin(), process_datas.end());
    std::sort(count_sorted_pds.begin(), count_sorted_pds.end(),
            [](const ProcessKV &lhs, const ProcessKV &rhs) {
                return lhs.second.count > rhs.second.count; });

    std::stringstream head;
    head << 
        setw(digits(max_instr)) << "Count" <<
        setw(6) << "Pid" << "  " <<
        setw(NAMELEN) << "Name" << "  " <<
        setw(sizeof(target_ulong) * 2) << "Asid" <<
        "  " << setw(digits(max_instr)) << "First" << 
        "      " << setw(digits(max_instr)) << "Last" << endl;
    fprintf(fp, "%s", head.str().c_str());
    for (auto &pd_kv : count_sorted_pds) {
        const NamePid &namepid = pd_kv.first;
        const ProcessData &pd = pd_kv.second;
        //        if (pd.count >= sample_cutoff) {
            std::stringstream ss;
            ss <<
                setw(digits(max_instr)) << pd.count <<
                setw(6) << namepid.pid << "  " <<
                setw(NAMELEN) << pd.shortname << "  " <<
                setw(sizeof(target_ulong) * 2) <<
                hex << namepid.asid << dec << setfill(' ') <<
                "  " << setw(digits(max_instr)) << pd.first <<
                "  ->  " << setw(digits(max_instr)) << pd.last << endl;
            fprintf(fp, "%s", ss.str().c_str());
            //        }
    }

    fprintf(fp, "\n");

    std::vector<ProcessKV> first_sorted_pds(process_datas.begin(), process_datas.end());
    std::sort(first_sorted_pds.begin(), first_sorted_pds.end(),
            [](const ProcessKV &lhs, const ProcessKV &rhs) {
                return lhs.second.first < rhs.second.first; });

    for (auto &pd_kv : first_sorted_pds) {
        const ProcessData &pd = pd_kv.second;

        //        if (pd.count >= sample_cutoff) {
            fprintf(fp, "%" NAMELENS "s : [", pd.shortname.c_str());
            for (unsigned i = 0; i < num_cells; i++) {
                auto it = pd.cells.find(i);
                if (it == pd.cells.end() || it->second < 2) {
                    fprintf(fp, " ");
                } else {
                    fprintf(fp, "#");
                }
            }
            fprintf(fp, "]\n");
            //        }
    }

    fclose(fp);
}


static inline bool pid_ok(int pid) {
    if (pid < 4) {
        return false;
    }
    return true;
}


static inline bool check_proc(OsiProc *proc) {
    if (!proc) return false;
    if (pid_ok(proc->pid)) {
        int l = strlen(proc->name);
        for (int i=0; i<l; i++) 
            if (!isprint(proc->name[i])) 
                return false;
    }
    // 'ls', 'ps', 'nc' all are 2 characters
    // we don't believe 1-character cmd names
    // are there any?
    if (strlen(proc->name) < 2) return false;
    return true;
}


/* 
   proc assumed to be ok.
   register that we saw this proc at this instr count
   updating first / last instr and cell counts
*/
void saw_proc(CPUState *env, OsiProc *proc, uint64_t instr_count) {

    const NamePid namepid(proc->name ? proc->name : "", proc->pid, proc->asid);        
    ProcessData &pd = process_datas[namepid];
    if (pd.first == 0) {
        // first encounter of this name/pid -- create reasonable shortname
        pd.first = instr_count;
        unsigned count = ++name_count[namepid.name];
        std::string count_str(std::to_string(count));
        std::string shortname(namepid.name);
        if (shortname.size() >= 4 && shortname.compare(shortname.size() - 4, 4, ".exe") == 0) {
            shortname = shortname.substr(0, shortname.size() - 4); 
        }
        if (count > 1) {
            if (shortname.size() + count_str.size() > NAMELEN) {
                shortname = shortname.substr(0, NAMELEN - count_str.size()) + count_str;
            } else {
                shortname += count_str;
            }
        } else if (shortname.size() > NAMELEN) {
            shortname = shortname.substr(0, NAMELEN);
        }
        pd.shortname = "";
        for (uint32_t i=0; i<shortname.length(); i++) {
            if (isprint(shortname[i])) 
                pd.shortname += shortname[i];
            else
                pd.shortname += '_';
        }
        pd.shortname = shortname;
    }
    pd.count++;
    uint32_t cell = instr_count * scale;
    pd.cells[cell]++;
    pd.last = std::max(pd.last, instr_count);
}



// proc was seen from instr i1 to i2
void saw_proc_range(CPUState *env, OsiProc *proc, uint64_t i1, uint64_t i2) {
    if (debug) 
        printf ("saw_proc_range [%s,%d] (%" PRId64 " ..%" PRId64 ")\n", 
                proc->name, (int) proc->pid, i1, i2);

     uint64_t step = floor(1.0 / scale) / 2;
    // assume that last process was running from last asid change to basically now
    saw_proc(env, proc, i1);
    saw_proc(env, proc, i2);
//    printf ("step = %d\n", (int) step/3);
    for (uint64_t i=i1; i<=i2; i+=step/3) {
        saw_proc(env, proc, i);
    }
}



// when asid changes, try to figure out current proc, which can fail in which case
// the before_block_exec callback will try again at the start of each subsequent
// block until we succeed in determining current proc. 
// also, if proc has changed, we record the fact that a process was seen to be running
// from now back to last asid change
int asidstory_asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    // some fool trying to use asidstory for boot? 
    if (new_asid == 0) return 0;
    
    uint64_t curr_instr = rr_get_guest_instr_count();
    
	if (debug) printf ("\nasid changed @ %lu\n", curr_instr);
    
    if (process_mode == Process_known) {
        
        if (debug) printf ("process was known for last asid interval\n");
        
        // this means we knew the process during the last asid interval
        // so we'll record that info for later display
        saw_proc_range(env, first_good_proc, instr_first_good_proc, curr_instr - 100);
        
        // just trying to arrange it so that we only spit out asidstory plot
        // for a cell once.
        int cell = curr_instr * scale; 
        bool anychange = false;
        for (int i=0; i<cell; i++) {
            if (!status_c[i]) anychange=true;
            status_c[i] = true;
        }
        if (anychange) spit_asidstory();
    }    
    else {
        if (debug) printf ("process was not known for last asid interval %lu %lu\n", instr_first_good_proc, curr_instr);
    }
    
    process_mode = Process_unknown;   
    asid_at_asid_changed = new_asid;
    
    if (debug) printf ("asid_changed: process_mode unknown\n");

    return 0;
}



OsiProc *copy_proc(OsiProc *from, OsiProc *to) {
    if (to == NULL) 
        to = (OsiProc *) malloc(sizeof(OsiProc));
    else {
        if (to->name != NULL) free(to->name);
        if (to->pages != NULL) free(to->pages);
    }
    memcpy(to, from, sizeof(OsiProc));
    to->name = strdup(from->name);
    to->pages = NULL;
    return to;
}


static inline bool process_same(OsiProc *proc1, OsiProc *proc2) {
    if ((proc1->pid != proc2->pid) || (0 != strcmp(proc1->name, proc2->name))) 
        return false;
    return true;
}



// before every bb, mostly just trying to figure out current proc 
int asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {

    // NB: we only know max instr *after* replay has started which is why this is here
    if (max_instr == 0) {
        max_instr = replay_get_total_num_instructions();
        scale = ((double) num_cells) / ((double) max_instr); 
        if (debug) printf("max_instr = %" PRId64 "\n", max_instr);
    }

    // all this is about figuring out if and when we know the current process
    switch (process_mode) {
    case Process_known: {
        return 0;
        break;
    }
    case Process_unknown: {
        if (debug) printf("before_bb: process_mode unknown\n");
        OsiProc *current_proc = get_current_process(env);    
        if (check_proc(current_proc)) {
            // first good proc 
            first_good_proc = copy_osiproc_g(current_proc, first_good_proc);
            instr_first_good_proc = rr_get_guest_instr_count(); 
            process_mode = Process_suspicious;
            process_counter = PROCESS_GOOD_NUM;
            if (debug) printf ("before_bb: process_mode suspicious.  %d %s\n", (int) current_proc->pid, current_proc->name);
        }
        break;
    }
    case Process_suspicious: {
        OsiProc *current_proc = get_current_process(env);    
        if (check_proc(current_proc) && (process_same(current_proc, first_good_proc))) {
            // proc good and also stable
            process_counter--;
            if (debug) printf ("before_bb: counter = %d\n", process_counter);
            if (process_counter == 0) {
                // process deemed good enough
                process_mode = Process_known;
                PPP_RUN_CB(on_proc_change, env, asid_at_asid_changed, first_good_proc);
                if (debug) printf ("before_bb: process_mode known\n");
            }
        }
        else {
            // process either not good or not stable -- revert
            process_mode = Process_unknown;                    
            if (debug) printf ("before_bb: process_mode unknown\n");
        }
        break;        
    }
    default: {}
    }
    
    return 0;
}


bool init_plugin(void *self) {    
    panda_require("osi");
   
    // this sets up OS introspection API
    assert(init_osi_api());

    panda_cb pcb;    
    pcb.asid_changed = asidstory_asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    
    pcb.before_block_exec = asidstory_before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    
    panda_arg_list *args = panda_get_args("asidstory");
    num_cells = std::max(panda_parse_uint64_opt(args, "width", 100, "number of columns to use for display"), UINT64_C(80)) - NAMELEN - 5;
    //    sample_rate = panda_parse_uint32(args, "sample_rate", sample_rate);
    //    sample_cutoff = panda_parse_uint32(args, "sample_cutoff", sample_cutoff);
    status_c = (bool *) malloc(sizeof(bool) * num_cells);
    for (int i=0; i<num_cells; i++) status_c[i]=false;
    
    
    min_instr = 0;   
    return true;
}

void uninit_plugin(void *self) {
  spit_asidstory();
}


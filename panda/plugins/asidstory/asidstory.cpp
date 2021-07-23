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
#include <cmath>
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

#include "asidstory_ppp.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"


bool init_plugin(void *);
void uninit_plugin(void *);

bool summary_mode = false;


// callback for when process changes
PPP_PROT_REG_CB(on_proc_change);

}

PPP_CB_BOILERPLATE(on_proc_change);

#include<string>
#include <iostream>

using namespace std;

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

// number of cells in the ascii art figure representing window
// of last max_instr instructions
uint32_t num_cells = 80;
uint64_t max_instr = 0;


double scale = 0;


bool debug = false;
//bool debug = true;

#define MILLION 1000000
//#define NAMELEN 10
//#define NAMELENS "10"
#define NAMELEN 20
#define NAMELENS "20"

uint64_t a_counter = 0;
uint64_t b_counter = 0;


typedef std::string Name;
typedef uint32_t Pid;
typedef uint32_t Tid;
typedef uint64_t Asid;
typedef uint32_t Cell;
typedef uint64_t Count;
typedef uint64_t Instr;


//bool spit_out_total_instr_once = false;


bool proc_ok = false;
bool asid_just_changed = false;
OsiProc *first_good_proc = NULL;
uint64_t instr_first_good_proc;
target_ptr_t first_good_proc_tid = 0;
target_ptr_t first_good_proc_ppid = 0;

target_ulong asid_at_asid_changed;


uint64_t kernel_count = 0;
uint64_t user_count = 0;
std::map<target_ulong, uint64_t> asid_count;

struct Process {
    // these two identify a process, I am told
    Pid pid;
    uint64_t create_time;

    Process(Pid pid, uint64_t create_time) :
        pid(pid), create_time(create_time) {}

    bool operator<(const Process &rhs) const {
        if (pid < rhs.pid) return true;
        if (pid > rhs.pid) return false;
        if (create_time < rhs.create_time) return true;
        return false;
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


// list of names we've observed for this process
map<Process, set<Name>> process_names;
// list of thread ids for this process
map<Process, set<Pid>> process_tids;
// asid for this process
map<Process, Asid> process_asid;
// parent pid for this process
map<Process, Pid> process_ppid;


typedef std::pair<Process, ProcessData> ProcessKV;

// process ranges, as observed in time order
vector<tuple<Process,Tid,Instr,Instr>> proc_ranges;



// count for non-replay
uint64_t instr_count = 0;

// returns an instr count
// either using rr (if we are in replay)
// or by computing it if we are live
uint64_t get_instr_count() {
    if (rr_in_replay())
        return rr_get_guest_instr_count();
    else
        return instr_count;
}

#if 0
// for replay, this is meaningful
// for live, we return either current max
uint64_t get_total_num_instructions() {
    if (rr_in_replay()) {
        return replay_get_total_num_instructions();
    }
    else {
        return instr
    }
}}
#endif

static unsigned digits(uint64_t num) {
    return std::to_string(num).size();
}





/*
   proc assumed to be ok.
   register that we saw this proc at this instr count
   updating first / last instr and cell counts
*/
void saw_proc(std::map<Process, ProcessData> &process_datas,
              std::map<std::string, unsigned> &name_count,
              Process process, Tid tid, Instr instr_count) {

    ProcessData &pd = process_datas[process];
    if (pd.first == 0) {
        // first encounter of this name/pid -- create reasonable shortname
        pd.first = instr_count;
        string prnames = "[";
        for (auto name : process_names[process])
            prnames += name + " ";
        prnames += " / " + (to_string(tid)) + "]";
        unsigned count = ++name_count[prnames];
        std::string count_str(std::to_string(count));
        std::string shortname(prnames);
        if (shortname.size() >= 4 && shortname.compare(shortname.size() - 4, 4, ".exe") == 0) {
            shortname = shortname.substr(0, shortname.size() - 4);
        }
        if (count > 1) {
            // seen name before, must add -n
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


void process_all_proc_ranges(std::map<Process, ProcessData> &process_datas,
                             std::map<std::string, unsigned> &name_count) {

    // XXX what on earth is all this /2 and then step/3 about?
    uint64_t step = floor(1.0 / scale) / 2;

    for (auto ptup : proc_ranges) {
        auto [ process, tid, i1, i2 ] = ptup;
        saw_proc(process_datas, name_count, process, tid, i1);
        saw_proc(process_datas, name_count, process, tid, i2);
        for (uint64_t i=i1; i<=i2; i+=step/3)
            saw_proc(process_datas, name_count, process, tid, i);
    }
}


void spit_asidstory() {

    std::map<Process, ProcessData> process_datas;
    // if we see svchost more than once, e.g., we use this to append 1, 2, 3, etc to the name in our output
    std::map<std::string, unsigned> name_count;

    process_all_proc_ranges(process_datas, name_count);

    // if pandalog we dont write asidstory file
    if (pandalog) return;

    printf ("no pandalog -- output to file named asidstory\n");

    FILE *fp = fopen("asidstory", "w");

    std::vector<ProcessKV> count_sorted_pds(process_datas.begin(), process_datas.end());
    std::sort(count_sorted_pds.begin(), count_sorted_pds.end(),
            [](const ProcessKV &lhs, const ProcessKV &rhs) {
                return lhs.second.count > rhs.second.count; });

    std::stringstream head;
    head <<
        setw(digits(max_instr)) << "Count" <<
        setw(6) << "Pid" << "  " <<
        setw(NAMELEN) << "Name/tid" << "  " <<
        setw(sizeof(target_ulong) * 2) << "Asid" <<
        "  " << setw(digits(max_instr)) << "First" <<
        "      " << setw(digits(max_instr)) << "Last" << endl;
    fprintf(fp, "%s", head.str().c_str());
    for (auto &pd_kv : count_sorted_pds) {
        const Process &process = pd_kv.first;
        const ProcessData &pd = pd_kv.second;
        //        if (pd.count >= sample_cutoff) {
            std::stringstream ss;
            ss <<
                setw(digits(max_instr)) << pd.count <<
                setw(6) << process.pid << "  " <<
                setw(NAMELEN) << pd.shortname << "  " <<
                setw(sizeof(target_ulong) * 2) <<
                hex << process_asid[process] << dec << setfill(' ') <<
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


uint64_t check_proc_succ = 0;
uint64_t check_proc_tot = 0;
uint64_t check_proc_null = 0;

static inline bool check_proc(OsiProc *proc) {

    check_proc_tot++;

    if (!proc) check_proc_null ++;
    if (!proc) return false;
    if (proc->asid == 0 || proc->asid == -1)
        return false;
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
    check_proc_succ++;
    return true;
}



set <Process> all_procs;

// first_good_proc was seen from instructions
// instr_first_good_proc to instr_end (param)
// store that info for later use
void save_proc_range(uint64_t instr_end) {

    const Process process(first_good_proc->pid, first_good_proc->create_time);

    // add name alias
    process_names[process].insert(first_good_proc->name);
    // add to set of tids observed
    process_tids[process].insert(first_good_proc_tid);

    // really this process should have only one parent and it should not change
    if (process_ppid.count(process) == 0) {
        process_ppid[process] = first_good_proc->ppid;
    } else {
        // It's okay if the PPID was originally 1 (init) then changed to another process - just record init was the parent.
        // It's also okay if the PPID was non-1 (not init) but then changes to 1 (process was reaped)
        // We don't currently support arbitrary PPID changes (e.g., as caused by prctl)
        assert (process_ppid[process] == first_good_proc->ppid || process_ppid[process] == 1 || first_good_proc->ppid == 1);
    }

    // process asid also should not change
    if (process_asid.count(process) == 0)
        process_asid[process] = first_good_proc->asid;
    else {
        if (process_asid[process] != first_good_proc->asid)  {

            cout << "asid for process changed! " << first_good_proc->name << " pid=" << first_good_proc->pid << "\n";
            cout << "... was 0x" << hex << process_asid[process] << " is " << first_good_proc->asid << "\n";

/*
            GArray *procs = get_processes(first_cpu);
            if (procs != NULL) {
                for (int i=0; i<procs->len; i++) {
                    OsiProc *proc = &g_array_index(procs, OsiProc, i);
                    cout << "proc[pid=" << dec << proc->pid << ",create_time=" << proc->create_time
                         << ",name=" << proc->name << ",taskd=" << hex << proc->taskd << ",asid=" << proc->asid
                         << ",ppid=" << dec << proc->ppid << "]: ";
                    for (auto p : all_procs) {
                        if (p.pid == proc->pid && p.create_time == proc->create_time) {
                            cout << "asid=" << hex << process_asid[p] << " ppid=" << dec << process_ppid[p] << "\n";
                            for (auto name : process_names[p]) cout << "  name=" << name;
                            cout << "\n";
                            for (auto tid : process_tids[p]) cout << "  tid=" << tid;
                            break;
                        }
                    }
                    cout << "\n";
                }
            }
*/
        }
  //      assert (process_asid[process] == first_good_proc->asid);

      process_asid[process] = first_good_proc->asid;
    }


    all_procs.insert(process);

    if (debug) {
        cout << "saw_proc_range: instr[" << instr_first_good_proc << "..." << instr_end << "]";
        cout << " proc [asid=0x" << hex << first_good_proc->asid << dec;
        cout << ",ppid=" << first_good_proc->ppid << ",names=[";
        for (auto name : process_names[process])
            cout << name << ",";
        cout << "],tids=[";
        for (auto tid : process_tids[process])
            cout << tid << ",";
        cout << "]\n";
    }

    auto ptup = make_tuple(process, first_good_proc_tid, instr_first_good_proc, instr_end);
    proc_ranges.push_back(ptup);

    if (pandalog && !summary_mode) {
        Panda__AsidInfo ai;
        ai = PANDA__ASID_INFO__INIT;
        // these two uniquely id a process
        ai.pid = process.pid;
        ai.create_time = process.create_time;
        ai.ppid = first_good_proc->ppid;
        ai.asid = first_good_proc->asid;
        ai.names = (char **) malloc(sizeof(char*) * process_names[process].size());
        ai.n_names = process_names[process].size();
        int i=0;
        for (auto name : process_names[process])
            ai.names[i++] = strdup(name.c_str());
        ai.tids = (uint32_t *) malloc(sizeof(uint32_t) * process_tids[process].size());
        ai.n_tids = process_tids[process].size();
        i=0;
        for (auto tid : process_tids[process])
            ai.tids[i++] = tid;
        ai.start_instr = instr_first_good_proc;
        ai.end_instr = instr_end;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.asid_info = &ai;
        pandalog_write_entry(&ple);
    }
}


// when asid changes, try to figure out current proc, which can fail in which case
// the before_block_exec callback will try again at the start of each subsequent
// block until we succeed in determining current proc.
// also, if proc has changed, we record the fact that a process was seen to be running
// from now back to last asid change
bool asidstory_asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {

    // some fool trying to use asidstory for boot?
    if (new_asid == 0) return false;

    uint64_t curr_instr = get_instr_count();

    if (debug) printf ("\nasid changed @ %" PRIu64 " new_asid=%" PRIx64 "\n", (uint64_t) curr_instr, (uint64_t) new_asid);

    if (process_mode == Process_known) {

        if (debug) printf ("process was known for last asid interval\n");

        // this means we knew the process during the last asid interval
        // so we'll record that info for later display
        save_proc_range(curr_instr - 100);

        if (!pandalog) {
            // just trying to arrange it so that we only spit out asidstory plot
            // for a cell once.

            // only in replay do we know ahead of time scale
            // and thus can know when we've updated a new time cell
            if (rr_in_replay()) {
                int cell = curr_instr * scale;

                bool anychange = false;
                for (int i=0; i<cell; i++) {
                    if (!status_c[i]) anychange=true;
                    status_c[i] = true;
                }
                if (anychange) spit_asidstory();
            }

        }
    }
    else {
        if (debug) printf ("process was not known for last asid interval %" PRIu64 " %" PRIu64 "\n", instr_first_good_proc, curr_instr);
    }

    process_mode = Process_unknown;
    asid_at_asid_changed = new_asid;

    if (debug) printf ("asid_changed: process_mode unknown\n");

    return false;
}


OsiProc *asidstory_current_proc() {
    if (process_mode == Process_known)
        return first_good_proc;
    return NULL;
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


uint64_t start_time, next_check_time;

// before every bb, mostly just trying to figure out current proc
void asidstory_before_block_exec(CPUState *env, TranslationBlock *tb) {

    if (!rr_in_replay()) {
        // live -- spit asidstory once every second
        struct timeval t;
        gettimeofday(&t, NULL);
        if (t.tv_sec > next_check_time) {
            spit_asidstory();
            next_check_time = t.tv_sec;
        }
        instr_count += tb->icount; // num instr in this block
    }

    if (panda_in_kernel(env))
        kernel_count ++;
    else
        user_count ++;
    asid_count[panda_current_asid(env)] ++;

    // NB: we only know max instr *after* replay has started which is why this is here
    if (rr_in_replay()) {
        if (max_instr == 0) {
            max_instr = replay_get_total_num_instructions();// get_total_num_instructions();
            scale = ((double) num_cells) / ((double) max_instr);
            if (debug) cout << "max_instr = " << max_instr << " scale = " << scale << "\n"; // %" PRId64 "\n", max_instr);
        }
    }
    else {
        // live!
        max_instr = instr_count;
        scale = ((double) num_cells) / ((double) max_instr);
    }

    // all this is about figuring out if and when we know the current process
    switch (process_mode) {

    case Process_known: {
        OsiProc *current_proc = get_current_process(env);
        if (check_proc(current_proc)) {
            if (0 != strcmp(current_proc->name, first_good_proc->name)) {
                // process name changed -- execve?
                uint64_t curr_instr = get_instr_count();
                save_proc_range(curr_instr - 100);

                if (debug) {
                    cout << curr_instr << " process name changed while known\n";
                    printf("old=%s new=%s\n", first_good_proc->name, current_proc->name);
                }

                first_good_proc = copy_osiproc(current_proc, first_good_proc);
                OsiThread *t = get_current_thread(env);
                first_good_proc_tid = t->tid;
                instr_first_good_proc = curr_instr;
                process_mode = Process_suspicious;
                process_counter = PROCESS_GOOD_NUM;
                PPP_RUN_CB(on_proc_change, env, asid_at_asid_changed, first_good_proc);
                free_osithread(t);
            }
        }
        free_osiproc(current_proc);
        break;
    }
    case Process_unknown: {
        if (debug) printf("before_bb: process_mode unknown\n");
        OsiProc *current_proc = get_current_process(env);
        if (check_proc(current_proc)) {
            // first good proc
            first_good_proc = copy_osiproc(current_proc, first_good_proc);
            OsiThread *t = get_current_thread(env);
            first_good_proc_tid = t->tid;
            first_good_proc_ppid = first_good_proc->ppid;
            instr_first_good_proc = get_instr_count();
            process_mode = Process_suspicious;
            process_counter = PROCESS_GOOD_NUM;
            if (debug) printf ("before_bb: process_mode suspicious.  %d %s\n", (int) current_proc->pid, current_proc->name);
            free_osithread(t);
        }
        free_osiproc(current_proc);
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
        free_osiproc(current_proc);
        break;
    }
    default: {}
    }

    return;
}


static_assert(CHAR_BIT == 8);
static_assert(sizeof(char) == sizeof(uint8_t)); /* this is pointless, sizeof(char) == 1 by definition, and uint8_t must be exactly 8 bits if defined */
string read_guest_null_terminated_string(CPUState *cpu, uint64_t addr) {
    char buffer[1024];
    size_t len; /* len must escape the loop scope */
    for (len = 0; len < sizeof(buffer); ++len)
        if ((panda_virtual_memory_read(cpu, addr+len, (uint8_t*)&buffer[len], 1) != 0) ||
            (buffer[len] == 0))
            break;
    return string(buffer, len);
}



// 59 long sys_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
void execve_cb(CPUState *cpu, target_ptr_t pc, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp) {
    string filename_s = read_guest_null_terminated_string(cpu, filename);
    cout << "Entering execve -- filename = [" << filename_s << "\n";
}


// 322 long sys_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
void execveat_cb (CPUState* cpu, target_ptr_t pc, int dfd, target_ptr_t filename, target_ptr_t argv, target_ptr_t envp, int flags) {
//void execveat(CPUState *cpu, target_ulong pc, uint64_t filename, uint64_t argv, uint64_t envp, int flags) {
    string filename_s = read_guest_null_terminated_string(cpu, filename);
    cout << "Entering execveat -- filename = [" << filename_s << "\n";
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

    #if defined(TARGET_PPC)
        fprintf(stderr, "[ERROR] asidstory: PPC architecture not supported by syscalls2!\n");
        return false;
    #else
        panda_require("syscalls2");
        assert(init_syscalls2_api());
        PPP_REG_CB("syscalls2", on_sys_execve_enter, execve_cb);
        PPP_REG_CB("syscalls2", on_sys_execveat_enter, execveat_cb);
    #endif

    panda_arg_list *args = panda_get_args("asidstory");
    num_cells = std::max(panda_parse_uint64_opt(args, "width", 100, "number of columns to use for display"), UINT64_C(80)) - NAMELEN - 5;

    summary_mode = panda_parse_bool_opt(args, "summary", "summary mode (for pandalog)");
    if (!pandalog) {
        printf ("NOT pandalooging\n");
        status_c = (bool *) malloc(sizeof(bool) * num_cells);
        for (int i=0; i<num_cells; i++) status_c[i]=false;
    }
    else {
        printf ("pandalogging on\n");
    }

    printf ("asidstory: summary_mode = %d\n", summary_mode);

    struct timeval t;
    gettimeofday(&t, NULL);

    next_check_time = t.tv_sec+1;

    return true;
}

void uninit_plugin(void *self) {


    printf ("user %" PRId64 "\n", user_count);
    printf ("kernel %" PRId64 "\n", kernel_count);
    for (auto &kvp : asid_count) {
        printf ("  " TARGET_PTR_FMT " %" PRId64 "\n", kvp.first, kvp.second);
    }


    if (pandalog && summary_mode) {

        std::map<Process, ProcessData> process_datas;
        std::map<std::string, unsigned> name_count;

        process_all_proc_ranges(process_datas, name_count);

        for (auto &kvp : process_datas) {
            auto &process = kvp.first;
            auto &pd = kvp.second;
            Panda__AsidInfo *ai = (Panda__AsidInfo *) malloc(sizeof(Panda__AsidInfo));
            *ai = PANDA__ASID_INFO__INIT;
            ai->pid = process.pid;
            ai->create_time = process.create_time;
            ai->ppid = process_ppid[process];
            ai->asid = process_asid[process];
            ai->names = (char **) malloc(sizeof(char*) * process_names[process].size());
            int i=0;
            for (auto name : process_names[process])
                ai->names[i++] = strdup(name.c_str());
            ai->n_names = process_names[process].size();
            ai->tids = (uint32_t *) malloc(sizeof(uint32_t) * process_tids.size());
            ai->n_tids = process_tids.size();
            i=0;
            for (auto tid : process_tids[process])
                ai->tids[i++] = tid;
            ai->start_instr = pd.first;
            ai->end_instr = pd.last;
            ai->has_count = 1;
            ai->count = pd.count;
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.asid_info = ai;
            pandalog_write_entry(&ple);
            free(ai);
        }
    }

    spit_asidstory();


    cout << "check_proc_succ = " << check_proc_succ << "\n";
    cout << "check_proc_tot  = " << check_proc_tot << "\n";

}

/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "panda/plugin.h"

// Taint Includes
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"

// OSI Includes
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "ida_taint2_api.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

FILE *pidpclog;

struct IDATaintReport {
    target_pid_t pid;
    target_ptr_t pc;
    uint32_t label;
    bool in_kernel;
};

template <typename T> inline void hash_combine(std::size_t &seed, const T &v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

// Inject the hash function for IDATaintReport into the std namespace, allows us
// to store IDATaintReport in an unordered set.
namespace std
{
template <> struct hash<IDATaintReport> {
    using argument_type = IDATaintReport;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        std::size_t h = 0;
        hash_combine(h, s.pid);
        hash_combine(h, s.pc);
        hash_combine(h, s.label);
        hash_combine(h, s.in_kernel);
        return h;
    }
};
} // namespace std

// Also needed to use an unordered set (probably in case there is a hash
// collision).
bool operator==(const IDATaintReport &lhs, const IDATaintReport &rhs)
{
    return (lhs.pid == rhs.pid) && (lhs.pc == rhs.pc) &&
            (lhs.label == rhs.label) && (lhs.in_kernel == rhs.in_kernel);
}

// Keep track of reports that we've already seen (ignoring the TCN)
static std::unordered_set<IDATaintReport> seen;

// Keep track of the minimum taint compute number seen for each report
static std::unordered_map<IDATaintReport, uint32_t> mintcn_for_report;

static std::unordered_map<target_pid_t, std::string> name_for_pid;

void taint_state_changed(Addr a, uint64_t size)
{
    // Get current PID (if in user-mode and OSI gave us a process) and PC.
    IDATaintReport report;
    report.pc = panda_current_pc(first_cpu);
    report.pid = 0;

    // unfortunately 0 is a valid PID for a non-kernel process so need to
    // distinguish between the two cases another way
    report.in_kernel = panda_in_kernel(first_cpu);
    if (false == report.in_kernel) {
        OsiProc *proc = get_current_process(first_cpu);
        report.pid = proc ? proc->pid : 0;

        // haven't seen this process ID before - save its name to report later
        if (name_for_pid.find(report.pid) == name_for_pid.end()) {
            std::string process_name(proc->name);
            name_for_pid[report.pid] = process_name;
        }

        if (proc) {
            free_osiproc(proc);
        }
    }

    uint32_t mintcn = UINT32_MAX;
    for (int i = 0; i < size; i++) {
        a.off = i;
        uint32_t label_count = taint2_query(a);
        std::vector<uint32_t> labels(label_count);
        taint2_query_set(a, labels.data());

        if (label_count > 0) {
            // the TCNs for a particular pid/pc/label triplet do not necessarily
            // arrive in non-decreasing order, so have to calculate as go and
            // write out final value at end
            uint32_t cur_tcn = taint2_query_tcn(a);
            if (mintcn > cur_tcn) {
                mintcn = cur_tcn;
            }

            for (int j = 0; j < label_count; j++) {
                report.label = labels[j];
                if (seen.find(report) == seen.end()) {
                    seen.insert(report);
                    mintcn_for_report[report] = mintcn;
                } else if (mintcn_for_report[report] > mintcn) {
                    mintcn_for_report[report] = mintcn;
                }
            }
        }
    }
}

const char *filename;

const char *ida_taint2_get_filename(void) {
    return filename;
}

bool init_plugin(void *self)
{
    // Setup OSI
    panda_require("osi");
    assert(init_osi_api());

    // Setup Taint
    panda_require("taint2");
    assert(init_taint2_api());
    PPP_REG_CB("taint2", on_taint_change, taint_state_changed);
    taint2_track_taint_state();

    // Turn on the precise program counter so we can highlight the exact
    // instruction.
    panda_enable_precise_pc();

    // Setup CSV file.
    panda_arg_list *args = panda_get_args("ida_taint2");
    filename = panda_parse_string(args, "filename", "ida_taint2.csv");

    // Open up a CSV file and write the metadata and header.
    // get build date in ISO 8601 format
    struct tm build_tm;
    memset(&build_tm, 0, sizeof(struct tm));
    strptime(__DATE__, "%b %d %Y", &build_tm);
    char build_date[16];
    strftime(build_date, 16, "%Y-%m-%d", &build_tm);
    
    // need UTC execution time in ISO 8601 format
    time_t s_since_epoch = time(NULL);
    struct tm exec_tm;
    gmtime_r(&s_since_epoch, &exec_tm);
    char time_string[64];
    strftime(time_string, 64, "%FT%TZ", &exec_tm);
    pidpclog = fopen(filename, "w");
    fprintf(pidpclog, "PANDA Build Date,%s\n", build_date);
    fprintf(pidpclog, "Execution Timestamp,%s\n", time_string);
    fprintf(pidpclog, "process name,pid,pc,label,minimum tcn\n");
    fclose(pidpclog);

    return true;
}

void uninit_plugin(void *self)
{
    // Now that we know the minimum taint compute number for each taint report,
    // we can save the information to the file.
    if (seen.size() > 0) {
        pidpclog = fopen(filename, "a+");
        for (auto it = seen.begin(); it != seen.end(); ++it) {
            uint32_t cur_mintcn = mintcn_for_report[*it];
            if (it->in_kernel) {
                fprintf(pidpclog, "(kernel)," TARGET_PID_FMT ",0x" TARGET_PTR_FMT ",%u,%u\n",
                        it->pid, it->pc, it->label, cur_mintcn);
            } else {
                fprintf(pidpclog, "%s," TARGET_PID_FMT ",0x" TARGET_PTR_FMT ",%u,%u\n",
                        name_for_pid[it->pid].c_str(), it->pid, it->pc,
                        it->label, cur_mintcn);
            }
        }
        fclose(pidpclog);
    }
}

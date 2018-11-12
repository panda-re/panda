/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <unordered_set>

#include "panda/plugin.h"

// Taint Includes
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"

// OSI Includes
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

FILE *pidpclog;

struct PidPcPair {
    target_ulong pid;
    target_ulong pc;
};

static TranslationBlock *current_tb = NULL;

// Inject the hash function for PidPcPair into the std namespace, allows us to
// store PidPcPair in an unordered set.
namespace std
{
template <> struct hash<PidPcPair> {
    using argument_type = PidPcPair;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<target_ulong>{}(s.pid);
        result_type const h2 = std::hash<target_ulong>{}(s.pc);
        return h1 ^ (h2 << 1);
    }
};
} // namespace std

// Also needed to use an unordered set (probably in case there is a hash
// collision).
bool operator==(const PidPcPair &lhs, const PidPcPair &rhs)
{
    return lhs.pid == rhs.pid && lhs.pc == rhs.pc;
}

void taint_state_changed(Addr a, uint64_t size)
{
    // We keep track of pairs of PIDs and PCs that we've already seen since we
    // only need to write out distinct pairs once.
    static std::unordered_set<PidPcPair> seen;

    // Get current PID and PC.
    OsiProc *proc = get_current_process(first_cpu);
    PidPcPair p;
    p.pid = proc ? proc->pid : 0;
    p.pc = panda_current_pc(first_cpu);
    if (proc) {
        free_osiproc_g(proc);
    }

    // Figure out which entries are tainted.
    uint32_t num_tainted = 0;
    for (int i = 0; i < size; i++) {
        a.off = i;
        num_tainted += (taint2_query(a) != 0);
    }

    // If its tainted and we haven't seen this PID\PC pair before, write to the
    // file.
    if (num_tainted && seen.find(p) == seen.end()) {
        seen.insert(p);

        // It should not be possible for current_tb to be null.
        assert(current_tb != NULL);
        fprintf(pidpclog, "%lu,%lu,%lu\n", (uint64_t)p.pid,
                (uint64_t)current_tb->pc, (uint64_t)current_tb->size);
    }
}

int before_block_exec(CPUState *cpu, TranslationBlock *tb)
{
    current_tb = tb;
    return 0;
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

    // Setup CSV file.
    panda_arg_list *args = panda_get_args("ida_taint2");
    const char *filename =
        panda_parse_string(args, "filename", "ida_taint2.csv");

    // Open up a CSV file and write the header.
    pidpclog = fopen(filename, "w");
    fprintf(pidpclog, "pid,tb_pc,tb_size\n");

    // Register before block exec so we can track the translation block
    panda_cb pcb;
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self)
{
    fclose(pidpclog);
}

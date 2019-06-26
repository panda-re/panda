/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Mark A. Mankins
 *  Laura L. Mann
 *
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#include <unordered_set>

#include "panda/plugin.h"

// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

static FILE *coveragelog;

enum coverage_mode {
    MODE_PROCESS = 0,
    MODE_ASID = 1
};

struct RecordID {
    target_ulong pidOrAsid;
    target_ulong tid;
    target_ulong pc;
};

// Inject the hash function for RecordID into the std namespace, allows us to
// store RecordID in an unordered set.
namespace std
{
template <> class hash<RecordID> {
public:
    using argument_type = RecordID;
    using result_type = size_t;
    result_type operator()(argument_type const &s) const noexcept
    {
        // Combining hashes, see C++ reference:
        // https://en.cppreference.com/w/cpp/utility/hash
        result_type const h1 = std::hash<target_ulong>{}(s.pidOrAsid);
        result_type const h2 = std::hash<target_ulong>{}(s.pc);
        result_type const h3 = std::hash<target_ulong>{}(s.tid);
        return h1 ^ (h2 << 2) ^ (h3 << 1);
    }
};
}
// namespace std

// Also needed to use an unordered set (probably in case there is a hash
// collision).
bool operator==(const RecordID &lhs, const RecordID &rhs)
{
    bool result = (lhs.pidOrAsid == rhs.pidOrAsid) && (lhs.pc == rhs.pc) &&
            (lhs.tid == rhs.tid);
    return result;
}

coverage_mode mode = MODE_ASID;

void write_process_record(RecordID id, uint64_t size)
{
    // Get the process name
    char *process_name = NULL;
    bool in_kernel = panda_in_kernel(first_cpu);
    if (!in_kernel) {
        OsiProc *proc = get_current_process(first_cpu);
        if (NULL != proc) {
            process_name = g_strdup(proc->name);
            free_osiproc(proc);
        } else {
            process_name = g_strdup("(unknown)");
        }
    } else {
        process_name = g_strdup("(kernel)");
    }

    // Log coverage data
    // process and thread ID are in decimal, as that is the radix
    // used by most tools that produce human readable output
    fprintf(coveragelog,
            "%s," TARGET_FMT_lu "," TARGET_FMT_lu ",%lu,0x"
            TARGET_FMT_lx ",%lu\n",
            process_name,
            id.pidOrAsid, id.tid, static_cast<uint64_t>(in_kernel),
            id.pc, size);
    g_free(process_name);
}

int before_block_exec_process_full(CPUState *cpu, TranslationBlock *tb)
{
    RecordID id;
    id.pc = tb->pc;
    OsiThread *thread = get_current_thread(cpu);
    if (NULL != thread) {
        id.pidOrAsid = thread->pid;
        id.tid = thread->tid;
        free_osithread(thread);
    } else {
        id.pidOrAsid = 0;
        id.tid = 0;
    }

    write_process_record(id, static_cast<uint64_t>(tb->size));

    return 0;
}

int before_block_exec_process_unique(CPUState *cpu, TranslationBlock *tb)
{
    // We keep track of PID/TID/PC tuples that we've already seen
    // since we only need to write out distinct tuples once.
    static std::unordered_set<RecordID> seen;

    RecordID id;
    id.pc = tb->pc;

    // Get process id
    OsiThread *thread = get_current_thread(cpu);

    // Create the tuple of process id, thead id, and program counter
    if (NULL != thread) {
        id.pidOrAsid = thread->pid;
        id.tid = thread->tid;
        free_osithread(thread);
    } else {
        id.pidOrAsid = 0;
        id.tid = 0;
    }

    // Have we seen this block before?
    if (seen.find(id) == seen.end()) {

        // No!  Put it into the list.
        seen.insert(id);

        write_process_record(id, static_cast<uint64_t>(tb->size));
    }

    return 0;
}

void write_asid_record(RecordID id, uint64_t size)
{
    // Want ASID to be output in hex to match what asidstory produces
    fprintf(coveragelog,
            "0x" TARGET_FMT_lx ",%lu,0x" TARGET_FMT_lx ",%lu\n",
            id.pidOrAsid,
            static_cast<uint64_t>(panda_in_kernel(first_cpu)), id.pc, size);
}

int before_block_exec_asid_full(CPUState *cpu, TranslationBlock *tb)
{
    RecordID id;
    id.pc = tb->pc;
    id.pidOrAsid = panda_current_asid(first_cpu);
    id.tid = 0;
    write_asid_record(id, static_cast<uint64_t>(tb->size));
    return 0;
}

int before_block_exec_asid_unique(CPUState *cpu, TranslationBlock *tb)
{
    // We keep track of pairs of ASIDs and PCs that we've already seen
    // since we only need to write out distinct pairs once.
    static std::unordered_set<RecordID> seen;

    RecordID id;
    id.pc = tb->pc;

    id.pidOrAsid = panda_current_asid(first_cpu);
    id.tid = 0;
    if (seen.find(id) == seen.end()) {
        seen.insert(id);
        write_asid_record(id, static_cast<uint64_t>(tb->size));
    }

    return 0;
}

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA
extern "C" {
bool init_plugin(void *self);
void uninit_plugin(void *self);
}

bool init_plugin(void *self)
{
    // Get Plugin Arguments
    panda_arg_list *args = panda_get_args("coverage");
    const char *filename =
        panda_parse_string(args, "filename", "coverage.csv");
    printf("%soutput file name %s\n", PANDA_MSG, filename);

    const char *mode_arg;
    if (OS_UNKNOWN == panda_os_familyno) {
        mode_arg = panda_parse_string_opt(args, "mode", "asid",
                "type of segregation used for blocks (process or asid)");
    } else {
        mode_arg = panda_parse_string_opt(args, "mode", "process",
                "type of segregation used for blocks (process or asid)");
    }
    if (0 == strcmp(mode_arg, "asid")) {
        mode = MODE_ASID;
    } else if (0 == strcmp(mode_arg, "process")) {
        mode = MODE_PROCESS;
    } else {
        LOG_ERROR("invalid mode (%s) provided", mode_arg);
        return false;
    }

    uint32_t buffer_size = panda_parse_uint32_opt(args, "buffer_size", BUFSIZ,
        "size of output buffer (default=BUFSIZ)");
    // Don't use LOG_INFO because I always want to see the informational
    // messages (which aren't on by default)
    printf("%sfile buffer_size %d\n", PANDA_MSG, buffer_size);

    bool log_all_records = panda_parse_bool_opt(args, "full",
            "log all records instead of just uniquely identified ones");
    printf("%slog all records %s\n", PANDA_MSG,
            PANDA_FLAG_STATUS(log_all_records));

    if (MODE_PROCESS == mode) {
        if (OS_UNKNOWN == panda_os_familyno) {
            LOG_WARNING("no OS specified, switching to asid mode");
            mode = MODE_ASID;
        } else {
            printf("%smode process\n", PANDA_MSG);
            panda_require("osi");
            assert(init_osi_api());
        }
    } else {
        printf("%smode asid\n", PANDA_MSG);
    }

    // Open the coverage CSV file, and set up the file buffering
    panda_cb pcb;
    coveragelog = fopen(filename, "w");
    if (BUFSIZ != buffer_size) {
        int buf_mode = _IOFBF;
        // If buffer_size is 0, then turn off buffering
        if (0 == buffer_size) {
            buf_mode = _IONBF;
        }
        // Let setvbuf take care of allocating and freeing buffer
        int ret_code = setvbuf(coveragelog, NULL, buf_mode, buffer_size);
        if (0 != ret_code) {
            LOG_ERROR("could not change buffer size");
            return false;
        }
    }

    // Output headers, and select appropriate callback
    // we're trying to avoid making decisions during data collection, especially
    // when logging all records, to make things go faster
    if (MODE_PROCESS == mode) {
        fprintf(coveragelog, "process\n");
        fprintf(coveragelog, "process name,process id,thread id,in kernel,"
                "block address,block size\n");
        if (log_all_records) {
            pcb.before_block_exec = before_block_exec_process_full;
        } else {
            pcb.before_block_exec = before_block_exec_process_unique;
        }
    } else {
        fprintf(coveragelog, "asid\n");
        fprintf(coveragelog, "asid,in kernel,block address,block size\n");
        if (log_all_records) {
            pcb.before_block_exec = before_block_exec_asid_full;
        } else {
            pcb.before_block_exec = before_block_exec_asid_unique;
        }
    }

    // Register callback
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) 
{
    fclose(coveragelog);
    coveragelog = NULL;
}

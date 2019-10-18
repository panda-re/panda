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

const char *DEFAULT_FILE = "coverage.csv";

// commands that can be accessed through the QEMU monitor
const char *MONITOR_HELP = "help";
constexpr size_t MONITOR_HELP_LEN = 4;
const char *MONITOR_ENABLE = "coverage_enable";
constexpr size_t MONITOR_ENABLE_LEN = 15;
const char *MONITOR_DISABLE = "coverage_disable";
constexpr size_t MONITOR_DISABLE_LEN = 16;


static FILE *coveragelog = NULL;

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

// the pointer passed in to init_plugin
void *coverage_plugin = nullptr;

coverage_mode mode = MODE_ASID;
panda_cb pcb_before_block_exec;
uint32_t buffer_size = BUFSIZ;
bool enabled = false;
bool before_block_exec_registered = false;

static void log_message(const char *message)
{
    printf("%s%s\n", PANDA_MSG, message);
}

static void log_message(const char *message1, const char *message2)
{
    printf("%s%s %s\n", PANDA_MSG, message1, message2);
}

static void log_message(const char *message, uint32_t number)
{
    printf("%s%s %d\n", PANDA_MSG, message, number);
}

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
            "%s," TARGET_FMT_lu "," TARGET_FMT_lu ",%" PRIu64 ","
            "0x" TARGET_FMT_lx ",%" PRIu64 "\n",
            process_name,
            id.pidOrAsid, id.tid, static_cast<uint64_t>(in_kernel),
            id.pc, size);
    g_free(process_name);
}

int before_block_exec_process_full(CPUState *cpu, TranslationBlock *tb)
{
    // part of workaround to broken enable/disable plugin callback framework
    if (!enabled) {
        return 0;
    }

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
    // part of workaround to broken enable/disable plugin callback framework
    if (!enabled) {
        return 0;
    }

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
            "0x" TARGET_FMT_lx ",%" PRIu64 ",0x" TARGET_FMT_lx ",%" PRIu64 "\n",
            id.pidOrAsid,
            static_cast<uint64_t>(panda_in_kernel(first_cpu)), id.pc, size);
}

int before_block_exec_asid_full(CPUState *cpu, TranslationBlock *tb)
{
    // part of workaround to broken enable/disable plugin callback framework
    if (!enabled) {
        return 0;
    }

    RecordID id;
    id.pc = tb->pc;
    id.pidOrAsid = panda_current_asid(first_cpu);
    id.tid = 0;
    write_asid_record(id, static_cast<uint64_t>(tb->size));
    return 0;
}

int before_block_exec_asid_unique(CPUState *cpu, TranslationBlock *tb)
{
    // part of workaround to broken enable/disable plugin callback framework
    if (!enabled) {
        return 0;
    }

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

bool enable_logging(const char *filename)
{
    // Open the coverage CSV file, and set up the file buffering
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

    // Output headers
    if (MODE_PROCESS == mode) {
        fprintf(coveragelog, "process\n");
        fprintf(coveragelog, "process name,process id,thread id,in kernel,"
                "block address,block size\n");
    } else {
        fprintf(coveragelog, "asid\n");
        fprintf(coveragelog, "asid,in kernel,block address,block size\n");
    }

    // Register callback
    // it would be nice if we could use panda_enable_callback and
    // panda_disable_callback to enable and disable instrumentation, but that
    // framework is broken - see public PANDA issue 451
    if (!before_block_exec_registered) {
        panda_register_callback(coverage_plugin, PANDA_CB_BEFORE_BLOCK_EXEC,
            pcb_before_block_exec);
        before_block_exec_registered = true;
    }

    enabled = true;
    return true;
}


void disable_logging()
{
    if (coveragelog != NULL) {
        // this is where we would like to call panda_disable_callback (assuming
        // the callback has been registered), if the framework were using the
        // callback's enabled flag properly - see public PANDA issue 451
        fclose(coveragelog);
        coveragelog = NULL;
        enabled = false;
    }
}

void process_enable_cmd(char *word)
{
    char *pequal;
    size_t wordlen;

    pequal=strchr(word, '=');
    if (pequal != NULL) {
        // extract after = as new filename
        wordlen = strlen(word);
        if (wordlen > (MONITOR_ENABLE_LEN+1)) {
            // I really, really don't want to allocate new memory
            // for the file name every time enable, and as I can't
            // predict the maximum filename length that doesn't
            // leave me with much choice on how to send the filename
            // to enable_logging
            enable_logging(pequal+1);
        } else {
            log_message("Instrumentation enabled without filename, "
                "using default of", DEFAULT_FILE);
            enable_logging(DEFAULT_FILE);
        }
    } else {
        log_message("Instrumentation enabled without filename, "
            "using default of", DEFAULT_FILE);
        enable_logging(DEFAULT_FILE);
    }
    // if enable_logging failed, it will already have spit out a
    // warning, which is most can do here
}

int monitor_callback(Monitor *mon, const char *cmd)
{
    char *cmd_copy = g_strdup(cmd);
    char *word;
    char *tokstatus;

    word = strtok_r(cmd_copy, " ", &tokstatus);
    do {
        if (0 == strncmp(MONITOR_HELP, word, MONITOR_HELP_LEN)) {
            // yes there is a nice monitor_printf function in monitor.h, but
            // attempting to include that file in a plugin causes great grief
            log_message("coverage_enable=filename:  start logging "
                    "coverage information to the named file");
            log_message("coverage_disable:  stop logging coverage "
                    "information and close the current file");
        } else if (0 == strncmp(MONITOR_DISABLE, word, MONITOR_DISABLE_LEN)) {
            if (enabled) {
                disable_logging();
            } else {
                log_message(
                  "Instrumentation not enabled, ignoring request to disable");
            }
        } else if (0 == strncmp(MONITOR_ENABLE, word, MONITOR_ENABLE_LEN)) {
            // we know word at least STARTS with coverage_enable
            if (!enabled) {
                process_enable_cmd(word);
            } else {
                log_message("Instrumentation already enabled, ignoring "
                        "request to enable");
            }
        }
        word = strtok_r(NULL, " ", &tokstatus);
    } while (word != NULL);
    g_free(cmd_copy);

    // return value is ignored, so doesn't matter what return
    return 1;
}

// These need to be extern "C" so that the ABI is compatible with QEMU/PANDA
extern "C" {
bool init_plugin(void *self);
void uninit_plugin(void *self);
}

bool init_plugin(void *self)
{
    coverage_plugin = self;

    // Get Plugin Arguments
    panda_arg_list *args = panda_get_args("coverage");
    const char *filename =
        panda_parse_string(args, "filename", DEFAULT_FILE);
    log_message("output file name", filename);

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

    buffer_size = panda_parse_uint32_opt(args, "buffer_size", BUFSIZ,
        "size of output buffer (default=BUFSIZ)");
    // Don't use LOG_INFO because I always want to see the informational
    // messages (which aren't on by default)
    log_message("file buffer_size", buffer_size);

    bool log_all_records = panda_parse_bool_opt(args, "full",
            "log all records instead of just uniquely identified ones");
    log_message("log all records", PANDA_FLAG_STATUS(log_all_records));

    if (MODE_PROCESS == mode) {
        if (OS_UNKNOWN == panda_os_familyno) {
            LOG_WARNING("no OS specified, switching to asid mode");
            mode = MODE_ASID;
        } else {
            log_message("mode process");
            panda_require("osi");
            assert(init_osi_api());
        }
    } else {
        log_message("mode asid");
    }

    bool start_disabled = panda_parse_bool_opt(args, "start_disabled",
            "start the plugin with instrumentation disabled");
    log_message("start disabled", PANDA_FLAG_STATUS(start_disabled));

    // remember what callback should be used when logging is enabled
    // we're trying to avoid making decisions during data collection, especially
    // when logging all records, to make things go faster
    if (MODE_PROCESS == mode) {
        if (log_all_records) {
            pcb_before_block_exec.before_block_exec =
                    before_block_exec_process_full;
        } else {
            pcb_before_block_exec.before_block_exec =
                    before_block_exec_process_unique;
        }
    } else {
        if (log_all_records) {
            pcb_before_block_exec.before_block_exec =
                    before_block_exec_asid_full;
        } else {
            pcb_before_block_exec.before_block_exec =
                    before_block_exec_asid_unique;
        }
    }

    bool all_ok = true;
    if (!start_disabled)
    {
        all_ok = enable_logging(filename);
    }

    if (all_ok)
    {
        panda_cb pcb;
        pcb.monitor = monitor_callback;
        panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    }

    return all_ok;
}

void uninit_plugin(void *self) 
{
    disable_logging();
}

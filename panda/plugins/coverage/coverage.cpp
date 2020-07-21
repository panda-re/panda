/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <memory>
#include <string>
#include <unordered_set>

#include "panda/plugin.h"

// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "PredicateBuilder.h"

#include "Block.h"
#include "RecordProcessor.h"
#include "BlockProcessorBuilder.h"

#include "utils.h"

using namespace coverage;

const char *DEFAULT_FILE = "coverage.csv";

// commands that can be accessed through the QEMU monitor
const char *MONITOR_HELP = "help";
constexpr size_t MONITOR_HELP_LEN = 4;
const std::string MONITOR_ENABLE = "coverage_enable";
const std::string MONITOR_DISABLE = "coverage_disable";

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

static std::unique_ptr<Predicate> predicate;

/**
 * Logs a message to stdout.
 */
static void log_message(const char *fmt, ...)
{
    std::string msg_fmt = PANDA_MSG;
    msg_fmt += " ";
    msg_fmt += fmt;
    va_list arglist;
    va_start(arglist, fmt);
    vprintf(msg_fmt.c_str(), arglist);
    va_end(arglist);
}

static std::unordered_set<Block> blocks;
static std::unique_ptr<RecordProcessor<Block>> processor;

static void callback(Block *block)
{
    processor->handle(*block);
}

static void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb)
{
    // Determine if we should instrument the current block.
    if (nullptr == processor || !predicate->eval(cpu, tb)) {
        return;
    }

    // Instrument!
    Block block {
        .addr = tb->pc,
        .size = tb->size
    };
    auto result = blocks.insert(block);
    auto block_ptr = &(*std::get<0>(result));

    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);

    insert_call(&insert_point, &callback, block_ptr);
}

static void disable_instrumentation()
{
    log_message("Disabling Instrumentation\n");
    panda_do_flush_tb();
    processor.reset();
}

static void enable_instrumentation(const std::string& filename)
{
    log_message("Enabling Instrumentation\n");
    panda_do_flush_tb();
    std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(panda_get_args("coverage"), panda_free_args);

    bool unique_output = panda_parse_bool_opt(args.get(), "unique", "output unique records only");
    std::string mode_arg = panda_parse_string_opt(args.get(), "mode", "asid-block", "coverage mode");

    BlockProcessorBuilder b;
    b.with_filename(filename);
    b.with_output_mode(mode_arg);
    if (unique_output) {
        b.with_unique_filter();
    }
    processor = b.build();
}

int monitor_callback(Monitor *mon, const char *cmd_cstr)
{
    std::string cmd = cmd_cstr;
    auto index = cmd.find("=");
    std::string filename = DEFAULT_FILE;
    if (std::string::npos != index) {
        filename = cmd.substr(index+1);
    }
    if (0 == cmd.find(MONITOR_DISABLE)) {
        disable_instrumentation();
    } else if (0 == cmd.find(MONITOR_ENABLE)) {
        enable_instrumentation(filename);
    }
    return 0;
}

bool init_plugin(void *self)
{
    PredicateBuilder pb;

    panda_arg_list *args = panda_get_args("coverage");
    std::string pc_arg = panda_parse_string_opt(args, "pc", "",
                                                "program counter range");
    if ("" != pc_arg) {
        auto dash_idx = pc_arg.find("-");
        auto start_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(0, dash_idx), NULL, 0));
        auto end_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(dash_idx + 1), NULL, 0));
        log_message("PC Range Filter = [" TARGET_FMT_lx ", " TARGET_FMT_lx "]\n", start_pc, end_pc);
        pb.with_pc_range(start_pc, end_pc);
    }

    std::string process_name = panda_parse_string_opt(args, "process_name", "", "the process to collect coverage from");
    if ("" != process_name) {
        log_message("Process Name Filter = %s\n", process_name.c_str());
        pb.with_process_name(process_name);
    }

    std::string privilege = panda_parse_string_opt(args, "privilege", "all", "collect coverage for a specific privilege mode" );
    if ("user" == privilege) {
        log_message("Privilege Filter = user mode\n");
        pb.in_kernel(false);
    } else if ("kernel" == privilege) {
        log_message("Privilege Filter = kernel mode\n");
        pb.in_kernel(true);
    }

    predicate = pb.build();

    panda_cb pcb;

    pcb.before_tcg_codegen = before_tcg_codegen;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, pcb);

    bool start_disabled = panda_parse_bool_opt(args, "start_disabled",
            "start the plugin with instrumentation disabled");
    log_message("start disabled", PANDA_FLAG_STATUS(start_disabled));

    bool all_ok = true;
    if (!start_disabled)
    {
        enable_instrumentation(DEFAULT_FILE);
    }

    if (all_ok)
    {
        pcb.monitor = monitor_callback;
        panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    }

    return all_ok;
}

void uninit_plugin(void *self)
{
    disable_instrumentation();
}

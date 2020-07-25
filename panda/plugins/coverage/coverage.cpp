/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <exception>
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
static std::unique_ptr<RecordProcessor<Block>> processor;

/**
 * Logs a message to stdout.
 */
static void log_message(const char *fmt, ...)
{
    std::string msg_fmt = PANDA_MSG;
    msg_fmt += " ";
    msg_fmt += fmt;
    msg_fmt += "\n";
    va_list arglist;
    va_start(arglist, fmt);
    vprintf(msg_fmt.c_str(), arglist);
    va_end(arglist);
}

static void callback(TranslationBlock *tb)
{
    Block block {
        .addr = tb->pc,
        .size = tb->size
    };
    processor->handle(block);
}

static void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb)
{
    // Determine if we should instrument the current block.
    if (nullptr == processor || !predicate->eval(cpu, tb)) {
        return;
    }

    // Instrument!
    TCGOp *insert_point = find_first_guest_insn();
    assert(NULL != insert_point);
    insert_call(&insert_point, &callback, tb);
}

static void disable_instrumentation()
{
    panda_do_flush_tb();
    processor.reset();
}

static void enable_instrumentation(const std::string& filename)
{
    panda_do_flush_tb();
    std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
        panda_get_args("coverage"), panda_free_args);

    bool log_all_records = panda_parse_bool_opt(args.get(), "full",
            "log all records instead of just uniquely identified ones");
    log_message("log all records %s", PANDA_FLAG_STATUS(log_all_records));
    std::string mode_arg = panda_parse_string_opt(args.get(), "mode",
        "asid-block", "coverage mode");

    BlockProcessorBuilder b;
    b.with_filename(filename)
     .with_output_mode(mode_arg);
    if (!log_all_records) {
        b.with_unique_filter();
    }
    processor = b.build();
}

int monitor_callback(Monitor *mon, const char *cmd_cstr)
{
    std::string cmd = cmd_cstr;
    if (0 == cmd.find(MONITOR_DISABLE)) {
        if (nullptr == processor) {
            log_message("Instrumentation not enabled, ignoring request to "
                "disable.");
            return 0;
        }
        log_message("Disabling instrumentation.");
        disable_instrumentation();
    } else if (0 == cmd.find(MONITOR_ENABLE)) {
        if (nullptr != processor) {
            log_message("Instrumentation already enabled, ignoring request to "
                "enable.");
            return 0;
        }
        auto index = cmd.find("=");
        std::string filename = DEFAULT_FILE;
        if (std::string::npos != index) {
            filename = cmd.substr(index+1);
            log_message("Enabling instrumentation with filename: %s",
                filename.c_str());
        } else {
            log_message("Enabling instrumentation with default filename: %s",
                filename.c_str());
        }
        enable_instrumentation(filename);
    }
    return 0;
}

bool init_plugin(void *self)
{
    PredicateBuilder pb;

    std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
        panda_get_args("coverage"), panda_free_args);

    // Parse PC range argument.
    std::string pc_arg = panda_parse_string_opt(args.get(), "pc", "",
        "program counter range");
    if ("" != pc_arg) {
        auto dash_idx = pc_arg.find("-");
        if (std::string::npos == dash_idx) {
            log_message("Could not parse \"pc\" argument. Format: <Start PC>-<End PC>");
            return false;
        }
        try {
            auto start_pc = try_parse<target_ulong>(pc_arg.substr(0, dash_idx));
            auto end_pc = try_parse<target_ulong>(pc_arg.substr(dash_idx + 1));
            if (end_pc < start_pc) {
                log_message("End PC must be smaller than Start PC.");
                return false;
            }
            log_message("PC Range Filter = [" TARGET_FMT_lx ", " TARGET_FMT_lx "]", start_pc, end_pc);
            pb.with_pc_range(start_pc, end_pc);
        } catch (std::invalid_argument& e) {
            log_message("Could not parse PC Range argument: %s", pc_arg.c_str());
            return false;
        } catch (std::overflow_error& e) {
            log_message("PC range outside of valid address space for target.");
            return false;
        }
    }

    std::string process_name = panda_parse_string_opt(args.get(), "process_name", "", "the process to collect coverage from");
    if ("" != process_name) {
        log_message("Process Name Filter = %s", process_name.c_str());
        pb.with_process_name(process_name);
    }

    std::string privilege = panda_parse_string_opt(args.get(), "privilege", "all", "collect coverage for a specific privilege mode" );
    if ("user" == privilege) {
        log_message("Privilege Filter = user mode");
        pb.in_kernel(false);
    } else if ("kernel" == privilege) {
        log_message("Privilege Filter = kernel mode");
        pb.in_kernel(true);
    } else if ("all" != privilege) {
        log_message("Privilege filter must be be user, kernel, or all.");
        return false;
    }

    predicate = pb.build();

    panda_cb pcb;

    pcb.before_tcg_codegen = before_tcg_codegen;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, pcb);

    bool start_disabled = panda_parse_bool_opt(args.get(), "start_disabled",
            "start the plugin with instrumentation disabled");
    log_message("start disabled %s", PANDA_FLAG_STATUS(start_disabled));

    std::string filename = panda_parse_string_opt(args.get(), "filename",
        DEFAULT_FILE, "the filename to use for output");
    log_message("output file name %s", filename.c_str());

    if (!start_disabled)
    {
        enable_instrumentation(filename);
    }

    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    return true;
}

void uninit_plugin(void *self)
{
    disable_instrumentation();
}

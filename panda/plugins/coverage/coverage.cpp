/* PANDABEGINCOMMENT
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <iostream>
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
#include "ModeBuilder.h"
#include "InstrumentationDelegate.h"
#include "EdgeInstrumentationDelegate.h"
#include "CoverageMonitorDelegate.h"

#include "UniqueFilter.h"
#include "EdgeCsvWriter.h"

#include "osi_subject.h"

#include "panda/tcg-utils.h"

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

static std::vector<std::shared_ptr<InstrumentationDelegate>> inst_dels;

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

static void after_loadvm(CPUState *cpu)
{
    notify_task_change_observers(cpu);
}

static void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb)
{
    // Determine if we should instrument.
    if (inst_dels.empty() || !predicate->eval(cpu, tb)) {
        return;
    }
    // Instrument!
    for (auto& del : inst_dels) {
        del->instrument(cpu, tb);
    }
}

static std::vector<CoverageMonitorDelegate *> monitor_delegates;

int monitor_callback(Monitor *mon, const char *cmd_cstr)
{
    std::string cmd = cmd_cstr;
    if (0 == cmd.find(MONITOR_DISABLE)) {
        log_message("Disabling instrumentation.");
        for (auto del : monitor_delegates) {
            try {
                del->handle_disable();
            } catch (std::system_error& err) {
                std::cerr << "Error disabling instrumentation: " << err.code().message() << "\n";
            }
        }
    } else if (0 == cmd.find(MONITOR_ENABLE)) {
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
        for (auto del : monitor_delegates) {
            try {
                del->handle_enable(filename);
            } catch (std::system_error& err) {
                std::cerr << "Error enabling instrumentation: " << err.code().message() << "\n";
            }
        }
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
                log_message("End PC cannot be smaller than Start PC.");
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

    // Parse Excluded PC range argument.
    std::string expc_arg = panda_parse_string_opt(args.get(), "exclude_pc", "",
        "excluded program counter range");
    if ("" != expc_arg) {
        auto dash_idx = expc_arg.find("-");
        if (std::string::npos == dash_idx) {
            log_message("Could not parse \"exclude_pc\" argument. Format: <Start PC>-<End PC>");
            return false;
        }
        try {
            auto start_pc = try_parse<target_ulong>(expc_arg.substr(0, dash_idx));
            auto end_pc = try_parse<target_ulong>(expc_arg.substr(dash_idx + 1));
            if (end_pc < start_pc) {
                log_message("Excluded End PC cannot be smaller than Start PC.");
                return false;
            }
            log_message("Excluded PC Range Filter = [" TARGET_FMT_lx ", " TARGET_FMT_lx "]", start_pc, end_pc);
            pb.without_pc_range(start_pc, end_pc);
        } catch (std::invalid_argument& e) {
            log_message("Could not parse Excluded PC Range argument: %s", expc_arg.c_str());
            return false;
        } catch (std::overflow_error& e) {
            log_message("Excluded PC range outside of valid address space for target.");
            return false;
        }
    }

    std::string process_name = panda_parse_string_opt(args.get(), "process_name", "", "the process to collect coverage from");

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

    std::string mode_arg = panda_parse_string_opt(args.get(), "mode",
        "asid-block", "coverage mode");

    bool log_all_records = panda_parse_bool_opt(args.get(), "full",
            "log all records instead of just uniquely identified ones");
    log_message("log all records %s", PANDA_FLAG_STATUS(log_all_records));

    bool summarize_records = panda_parse_bool_opt(args.get(), "summary",
            "summarize coverage per program");
    log_message("summarize coverage %s", PANDA_FLAG_STATUS(summarize_records));

    ModeBuilder mb(monitor_delegates);

    if ("" != process_name) {
        log_message("Process Name Filter = %s", process_name.c_str());
        mb.with_process_name_filter(process_name);
    }

    mb.with_filename(filename);
    mb.with_mode(mode_arg);
    if (!log_all_records) {
        mb.with_unique_filter();
    }
    if (start_disabled)
    {
        mb.with_start_disabled();
    }

    if (summarize_records) {
        mb.with_summarize_results();

        if (mode_arg != "osi-block") {
            log_message("Running with summary requires mode to be \"osi-block\"");
            return false;
        }
        if (log_all_records) {
            log_message("full mode is pointless when running in summary mode- disabling");
            log_all_records = false;
        }
    }

    // Parse hook_filter argument.
    std::string hook_filter_arg = panda_parse_string_opt(args.get(),
        "hook_filter", "", "hook_filter");
    if ("" != hook_filter_arg) {
        auto dash_idx = hook_filter_arg.find("-");
        if (std::string::npos == dash_idx) {
            log_message("Could not parse \"hook_filter\" argument. Format: <Pass PC>-<Block PC>");
            return false;
        }
        try {
            auto pass_pc = try_parse<target_ulong>(hook_filter_arg.substr(0, dash_idx));
            auto block_pc = try_parse<target_ulong>(hook_filter_arg.substr(dash_idx + 1));
            log_message("Hook Filter = [" TARGET_FMT_lx ", " TARGET_FMT_lx "]", pass_pc, block_pc);
            mb.with_hook_filter(pass_pc, block_pc);
        } catch (std::invalid_argument& e) {
            log_message("Could not parse hook filter argument: %s", hook_filter_arg.c_str());
            return false;
        } catch (std::overflow_error& e) {
            log_message("Hook filter outside of valid address space for target.");
            return false;
        }
    }

    try {
        inst_dels = mb.build();
    } catch (std::system_error& err) {
        std::cerr << "Error setting up instrumentation: "
                  << err.code().message() << "\n";
        return false;
    }

    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    pcb.after_loadvm = after_loadvm;
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    return true;
}

void uninit_plugin(void *self)
{
    // Disable any running coverage monitors - this ensures we write results when running in summary
    // mode and we close files when running in normal mode.
    for (auto del : monitor_delegates) {
        try {
            del->handle_disable();
        } catch (std::system_error& err) {
            std::cerr << "Error disabling instrumentation: " << err.code().message() << "\n";
        }
    }

    inst_dels.clear();
    // if we don't clear tb's when this exits we have TBs which can call
    // into our exited plugin.
    panda_do_flush_tb();
}

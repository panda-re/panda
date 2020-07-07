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

#include "panda/plugin.h"

// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "AlwaysTruePredicate.h"
#include "PcRangePredicate.h"
#include "CompoundPredicate.h"
#include "ProcessNamePredicate.h"
#include "UniqueAsidPredicate.h"
#include "UniqueOsiPredicate.h"

#include "CoverageMode.h"
#include "AsidBlockCoverageMode.h"
#include "OsiBlockCoverageMode.h"
#include "EdgeCoverageMode.h"

const char *DEFAULT_FILE = "coverage.csv";

// commands that can be accessed through the QEMU monitor
const char *MONITOR_HELP = "help";
constexpr size_t MONITOR_HELP_LEN = 4;
const char *MONITOR_ENABLE = "coverage_enable";
constexpr size_t MONITOR_ENABLE_LEN = 15;
const char *MONITOR_DISABLE = "coverage_disable";
constexpr size_t MONITOR_DISABLE_LEN = 16;

using namespace coverage2;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

#include "tcg.h"
//extern TCGContext tcg_ctx;

}

static bool enabled = false;
static std::unique_ptr<Predicate> predicate;
static std::unique_ptr<CoverageMode> mode;

static void log_message(const char *message)
{
    printf("%s%s\n", PANDA_MSG, message);
}

static void log_message(const char *message1, const char *message2)
{

    printf("%s%s %s\n", PANDA_MSG, message1, message2);
}

//static void log_message(const char *message, uint32_t number)
//{
//    printf("%s%s %d\n", PANDA_MSG, message, number);
//}

static void before_tcg_codegen(CPUState *cpu, TranslationBlock *tb)
{
    mode->process_block(cpu, tb);
}

bool enable_instrumentation()
{
    // register the translation callbacks

    // flush translation blocks
    return true;
}

void disable_instrumentation()
{
    //if (coveragelog != NULL) {
        // this is where we would like to call panda_disable_callback (assuming
        // the callback has been registered), if the framework were using the
        // callback's enabled flag properly - see public PANDA issue 451
    //    fclose(coveragelog);
    //    coveragelog = NULL;
    enabled = false;
    //}
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
            //enable_logging(pequal+1);
        } else {
            log_message("Instrumentation enabled without filename, "
                "using default of", DEFAULT_FILE);
            //enable_logging(DEFAULT_FILE);
        }
    } else {
        log_message("Instrumentation enabled without filename, "
            "using default of", DEFAULT_FILE);
        //enable_logging(DEFAULT_FILE);
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
                disable_instrumentation();
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


bool init_plugin(void *self)
{
    predicate = std::unique_ptr<Predicate>(new AlwaysTruePredicate);

    panda_arg_list *args = panda_get_args("coverage2");
    std::string pc_arg = panda_parse_string_opt(args, "pc", "",
                                                "program counter range");
    if ("" != pc_arg) {
        auto dash_idx = pc_arg.find("-");
        auto start_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(0, dash_idx), NULL, 0));
        auto end_pc = static_cast<target_ulong>(std::stoull(pc_arg.substr(dash_idx + 1), NULL, 0));
        std::unique_ptr<Predicate> pcrp(new PcRangePredicate(start_pc, end_pc));
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(pcrp)));
    }

    std::string process_name = panda_parse_string_opt(args, "process_name", "", "the process to collect coverage from");
    if ("" != process_name) {
        std::unique_ptr<Predicate> pnpred(new ProcessNamePredicate(process_name));
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(pnpred)));
    }

    std::string unique = panda_parse_string_opt(args, "unique", "", "only output unique blocks (asid or osi)");
    if ("asid" == unique) {
        std::unique_ptr<Predicate> uapred(new UniqueAsidPredicate);
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(uapred)));
    } else if ("osi" == unique) {
        std::unique_ptr<Predicate> uosipred(new UniqueOsiPredicate);
        predicate = std::unique_ptr<Predicate>(new CompoundPredicate(std::move(predicate), std::move(uosipred)));
    }

    std::string mode_arg = panda_parse_string_opt(args, "mode", "asid-block", "coverage mode");
    if ("asid-block" == mode_arg) {
        mode = std::unique_ptr<CoverageMode>(new AsidBlockCoverageMode("test.csv"));
    } else if ("osi-block" == mode_arg) {
        mode = std::unique_ptr<CoverageMode>(new OsiBlockCoverageMode("test.csv"));
        //mode = std::unique_ptr<CoverageMode>(new OsiBlockCoverageMode("test.csv"));
    } else if ("edge" == mode_arg) {
        mode = std::unique_ptr<CoverageMode>(new EdgeCoverageMode);
    }

    panda_cb pcb;

    pcb.before_tcg_codegen = before_tcg_codegen;
    panda_register_callback(self, PANDA_CB_BEFORE_TCG_CODEGEN, pcb);

    bool start_disabled = panda_parse_bool_opt(args, "start_disabled",
            "start the plugin with instrumentation disabled");
    log_message("start disabled", PANDA_FLAG_STATUS(start_disabled));

    bool all_ok = true;
    if (!start_disabled)
    {
        //all_ok = enable_logging(filename);
    }

    if (all_ok)
    {
        pcb.monitor = monitor_callback;
        panda_register_callback(self, PANDA_CB_MONITOR, pcb);
    }

    panda_require("osi");
    assert(init_osi_api());

    return all_ok;
}

void uninit_plugin(void *self)
{
}

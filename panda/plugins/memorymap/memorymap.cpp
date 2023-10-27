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
#include <cstdlib>
#include <string>

#include "panda/plugin.h"

const char *UNKNOWN_ITEM = "(unknown)";
const char *NO_PROCESS = "(no current process)";

extern "C" {
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

// list of instruction counts at which desire memory mapping information
std::unordered_set<uint64_t> instr_counts_set;

// the maximum instruction count for which desire information
uint64_t maximum_instr_count = 0;

// list of PCs at which desire memory mapping information
std::unordered_set<target_ulong> pcs_set;

bool translate_cb(CPUState *cpu, target_ulong pc);
int before_insn_exec_cb(CPUState *cpu, target_ulong pc);

// Parse string of delimited instruction count arguments to a set
void instrs_to_vec(const char *arg_list_str,
        std::unordered_set<uint64_t> & out) {
    // shamelessly stolen from callfunc.cpp and slightly tweaked
    if ((!arg_list_str)) { return; }    // Pre-condition

    size_t pos_start;
    size_t pos_end;
    std::string s(arg_list_str);
    std::string delim("-");
    size_t len = 0;

    out.clear();
    pos_start = 0;
    pos_end = s.find(delim);

    // 1 arg, no delim
    if (pos_end == std::string::npos) {
        out.insert((uint64_t)std::stoul(s, nullptr, 10));
        return;
    }

    // Delimited args
    while (pos_end != std::string::npos) {
        len = (pos_end - pos_start);
        out.insert((uint64_t)std::stoul(s.substr(pos_start, len), nullptr, 10));
        pos_start = (pos_end + delim.size());
        pos_end = s.find(delim, pos_start);
    }

    // No delim after last arg
    if (pos_start < (s.size() - 1)) {
        out.insert((uint64_t)std::stoul(s.substr(pos_start), nullptr, 10));
    }
}

// Parse string of delimited PC arguments to set
void pcs_to_vec(const char *arg_list_str,
        std::unordered_set<target_ulong> & out) {
    // shamelessly stolen from callfunc.cpp and slightly tweaked
    if ((!arg_list_str)) { return; }    // Pre-condition

    size_t pos_start;
    size_t pos_end;
    std::string s(arg_list_str);
    std::string delim("-");
    size_t len = 0;

    out.clear();
    pos_start = 0;
    pos_end = s.find(delim);

    // 1 arg, no delim
    if (pos_end == std::string::npos) {
        out.insert((target_ulong)std::stoul(s, nullptr, 0));
        return;
    }

    // Delimited args
    while (pos_end != std::string::npos) {
        len = (pos_end - pos_start);
        out.insert((target_ulong)std::stoul(s.substr(pos_start, len), nullptr, 0));
        pos_start = (pos_end + delim.size());
        pos_end = s.find(delim, pos_start);
    }

    // No delim after last arg
    if (pos_start < (s.size() - 1)) {
        out.insert((target_ulong)std::stoul(s.substr(pos_start), nullptr, 0));
    }
}

// instrument each instruction of interest as it is translated
bool translate_cb(CPUState *env, target_ulong pc) {
    // if neither PCs nor instructions are listed, then instrument every
    // instruction
    if (pcs_set.empty() && instr_counts_set.empty()) {
        return true;
    }

    // if the current PC is in the list of those care about, add instrumentation
    if (pcs_set.find(pc) != pcs_set.end()) {
        return true;
    }

    // if any instruction counts are specified, and the current instruction
    // count is less than the maximum instruction count desired, then add
    // instrumentation (recall that an instruction may be translated once and
    // executed many times, so any instruction translated before the count of
    // interest must be instrumented)
    uint64_t cur_instr = rr_get_guest_instr_count();
    if (cur_instr <= maximum_instr_count) {
        return true;
    }

    return false;
}

void dump_process_info(const char *in_kernel, target_ulong pc,
        uint64_t instr_count, const char *process_name, target_pid_t pid,
        target_pid_t tid, const char *name, const char *image,
        target_ptr_t image_base)
{
    printf("pc=0x" TARGET_PTR_FMT " instr_count=%" PRIu64 " process=%s pid="
           TARGET_PID_FMT " tid=" TARGET_PID_FMT " in_kernel=%s image_name="
           "%s image_path=%s ",
           pc, instr_count, process_name, pid, tid, in_kernel, name, image);
    if (0 == strcmp(UNKNOWN_ITEM, name)) {
        printf("image_base=%s\n", UNKNOWN_ITEM);
    } else {
        printf("image_base=0x" TARGET_PTR_FMT "\n", image_base);
    }
}

void dump_noprocess_info(const char * in_kernel, target_ulong pc,
        uint64_t instr_count, target_pid_t tid, const char *name,
        const char *image, target_ptr_t image_base) {
    printf("pc=0x" TARGET_PTR_FMT " instr_count=%" PRIu64 " process=%s pid=NA"
           " tid=" TARGET_PID_FMT " in_kernel=%s image_name=%s image_path=%s ",
           pc, instr_count, NO_PROCESS, tid, in_kernel, name, image);
    if (0 == strcmp(UNKNOWN_ITEM, name)) {
        printf("image_base=%s\n", UNKNOWN_ITEM);
    } else {
        printf("image_base=0x" TARGET_PTR_FMT "\n", image_base);
    }
}

int before_insn_exec_cb(CPUState *cpu, target_ulong pc) {
    uint64_t cur_instr = rr_get_guest_instr_count();

    // only output information if at a desired PC or instruction count - if
    // neither PCs nor instruction counts listed, then we want them all
    if (!pcs_set.empty() || !instr_counts_set.empty()) {
        if ((pcs_set.find(pc) == pcs_set.end()) &&
                (instr_counts_set.find(cur_instr) == instr_counts_set.end())) {
            return 0;
        }
    }

    bool found_lib = false;

    OsiProc *current = get_current_process(cpu);
    target_pid_t tid = 0;
    OsiThread *thread = get_current_thread(cpu);
    if (NULL != thread) {
        tid = thread->tid;
    }
    char *pname = NULL;
    if (NULL != current) {
        if (current->pid > 0) {
            pname = g_strdup(current->name);
        } else {
            pname = g_strdup("NA");
        }

        // dump info on the dynamic library for the current PC, if there is one
        OsiModule *m = get_mapping_by_addr(cpu, current, pc);
        if(m) {
            dump_process_info("false", pc, cur_instr, pname,
                    current->pid, tid, m->name, m->file, m->base);
            found_lib = true;
            // cleanup
            free_osimodule(m);
        }
    }

    if (!found_lib) {
        // dump info on the kernel module for the current PC, if there is one
        GArray *kms = get_modules(cpu);
        if (kms != NULL) {
            for (int i = 0; i < kms->len; i++) {
                OsiModule *km = &g_array_index(kms, OsiModule, i);
                if ((pc >= km->base) && (pc < (km->base + km->size))) {
                    if (NULL != current) {
                        dump_process_info("true", pc, cur_instr, pname,
                                current->pid, tid, km->name, km->file,
                                km->base);
                        found_lib = true;
                        break;
                    } else {
                        dump_noprocess_info("true", pc, cur_instr, tid,
                                km->name, km->file, km->base);
                        found_lib = true;
                        break;
                    }
                }
            }
            g_array_free(kms, true);
        }
    }

    if (!found_lib) {
        if (NULL != current) {
            dump_process_info("false", pc, cur_instr, pname, current->pid, tid,
                    UNKNOWN_ITEM, UNKNOWN_ITEM, 0);
        } else {
            dump_noprocess_info("false", pc, cur_instr, tid, UNKNOWN_ITEM,
                    UNKNOWN_ITEM, 0);
        }
    }

    // more cleanup
    if (NULL != thread) {
        free_osithread(thread);
    }
    if (NULL != current) {
        free_osiproc(current);
        g_free(pname);
    }

    // the return value is unused, so this doesn't really matter
    return 0;
}

bool init_plugin(void *self) {
    // get arguments - if neither pcs or instruction counts are provided,
    // information on EVERY instruction will be dumped - which could take quite
    // some time
    panda_arg_list *args = panda_get_args("memorymap");

    const char *instr_counts_str = nullptr;
    instr_counts_str = panda_parse_string_opt(args, "instr_counts", nullptr,
            "Decimal, dash delimited instruction counts at which to dump information");
    if (nullptr != instr_counts_str) {
        instrs_to_vec(instr_counts_str, instr_counts_set);

        // calculate the maximum instruction count, to make things go faster
        // later on
        for (std::unordered_set<uint64_t>::iterator it = instr_counts_set.begin();
                it != instr_counts_set.end(); ++it) {
            if (maximum_instr_count < *it) {
                maximum_instr_count = *it;
            }
        }
    }

    const char *pcs_str = nullptr;
    pcs_str = panda_parse_string_opt(args, "pcs", nullptr,
            "Hex, octal or decimal dash delimited PCs at which to dump information");
    if (nullptr != pcs_str) {
        pcs_to_vec(pcs_str, pcs_set);
    }

    if (instr_counts_set.empty() && pcs_set.empty()) {
        LOG_WARNING("all instructions will be instrumented");
    }

    panda_require("osi");
   
    // this sets up OS introspection API
    assert(init_osi_api());

    panda_enable_precise_pc();

    // getting notified when a particular instruction is about to be executed is
    // a two step process - first, you have to tell the translator to add code
    // to make the callback  (which will REALLY slow down execution), and then
    // you have to register a callback which is notified
    panda_cb pcb;
    pcb.insn_translate = translate_cb;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = before_insn_exec_cb;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    // nothing to do
}


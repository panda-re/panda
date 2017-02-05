


#define __STDC_FORMAT_MACROS

#include <algorithm>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {
#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}


#if defined(TARGET_I386) && !defined(TARGET_X86_64)

target_ulong asid_of_interest=0;

bool right_asid(CPUState *env) {
    return (panda_current_asid(env) == asid_of_interest);
}    


// this will run whenever we are in code that we have pri info for and file / line have changed
void on_line_change(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    if (!right_asid(env)) return;
    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        Panda__SrcInfoPri psi = PANDA__SRC_INFO_PRI__INIT; // pandalog_src_info_pri_create(file_Name, lno, "none");
        psi.filename = (char *) file_Name;
        psi.astnodename = NULL;
        psi.linenum = lno;
        psi.has_insertionpoint = 0;
        ple.pri_trace_src_info = &psi;
        pandalog_write_entry(&ple);
    }
    else {
        printf ("pri_trace: instr=%" PRIu64" pc=0x" TARGET_FMT_lx " file=[%s] func=[%s] line=%llu\n",
                rr_get_guest_instr_count(), pc, file_Name, funct_name, lno);
    }
}

#endif


bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    panda_arg_list *args = panda_get_args("general");
    const char *asid_s = panda_parse_string_req(args, "asid", "asid of the process to follow for pri_trace");
    asid_of_interest = strtoul(asid_s, NULL, 16);
    panda_require("pri");
    //    assert(init_pri_api());
    PPP_REG_CB("pri", on_before_line_change, on_line_change);
#endif
    return true;
}


void uninit_plugin(void *self) {
}


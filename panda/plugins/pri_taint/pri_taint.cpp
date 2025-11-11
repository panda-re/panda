#define __STDC_FORMAT_MACROS

#include <algorithm>
#include <vector>
#include <memory>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

// taint
#include "taint2/label_set.h"
#include "taint2/taint2.h"

// needed for callstack logging
#include "callstack_instr/callstack_instr.h"
// needed for strstr
#include <cstring>

extern "C" {
#include <hypercaller/hypercaller.h>

#include "panda/rr/rr_log.h"
#include "panda/plog.h"

#include "taint2/taint2_hypercalls.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

// needed for accessing type information on linux/elf based systems
#include "dwarf2/dwarf2_types.h"
#include "dwarf2/dwarf2_ext.h"

#include "callstack_instr/callstack_instr_ext.h"

// taint
#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel();
void set_loglevel(int new_loglevel);
}
bool linechange_taint = true;
bool hypercall_taint = true;
// bool chaff_bugs = false;
const char *global_src_filename = NULL;
uint64_t global_src_linenum;
unsigned global_ast_loc_id;
bool debug = false;
// uint64_t global_funcaddr;

#define dprintf(...) if (debug) { printf(__VA_ARGS__); fflush(stdout); }

Panda__SrcInfoPri *pandalog_src_info_pri_create(const char *src_filename, uint64_t src_linenum, const char *src_ast_node_name, unsigned ast_loc_id) {
    Panda__SrcInfoPri *si = (Panda__SrcInfoPri *) malloc(sizeof(Panda__SrcInfoPri));
    *si = PANDA__SRC_INFO_PRI__INIT;

    si->filename = (char *) src_filename;
    si->astnodename = (char *) src_ast_node_name;
    si->linenum = src_linenum;

    si->has_ast_loc_id = 1;
    si->ast_loc_id = ast_loc_id;

    si->has_insertionpoint = 1;
    // insert before
    si->insertionpoint = 1;
    return si;
}

// The following two functions are taken from taint_api.cpp
// We can figure out how to avoid code duplication later...
Addr make_maddr(uint64_t a) {
    Addr ma;
    ma.typ = MADDR;
    ma.val.ma = a;
    ma.off = 0;
    ma.flag = (AddrFlag) 0;
    return ma;
}

Addr make_greg(uint64_t r, uint16_t off) {
    Addr a;
    a.typ = GREG;
    a.val.gr = r;
    a.off = off;
    a.flag = (AddrFlag) 0;
    return a;
}

void print_membytes(CPUState *env, target_ulong address, target_ulong len) {
    unsigned char c = (unsigned char) 0;
    printf("Content: { ");
    for (int i = 0; i < len; i++) {
        if (panda_virtual_memory_read(env, address + i, (uint8_t *) &c, sizeof(char)) == -1) {
            printf(" XX");
        } else {
            printf("%02x ", c);
        }
    }
    printf("}\n");
}

struct args {
    CPUState *cpu;
    const char *src_filename;
    uint64_t src_linenum;
    unsigned ast_loc_id;
    // uint64_t funcaddr;
};

// max length of strnlen or taint query
#define LAVA_TAINT_QUERY_MAX_LEN (target_ulong)64ULL
#if defined(TARGET_I386) || defined(TARGET_ARM)
void lava_taint_query(CPUState *cpu, target_ulong buf, LocType loc_t, target_ulong buf_len, const char *astnodename) {
    dprintf("[pri_taint] Attempt to lava_taint_query\n");

    // can't do a taint query if it is not a valid register (loc) or if
    // the buf_len is greater than the register size (assume size of guest pointer)
    if (loc_t == LocReg && (buf >= CPU_NB_REGS || buf_len >= sizeof(target_ulong) ||
                buf_len == (target_ulong) -1)) {
        dprintf("[pri_taint] The register is not valid OR buf_len > register size\n");
        return;
    }
    if (loc_t == LocErr || loc_t == LocConst) {
        dprintf("[pri_taint] The Location is either error OR constant. Shouldn't happen based on pfun()\n");
        return;
    }
    if (!pandalog || !taint2_enabled()) {
        dprintf("[pri_taint] No Panda log or Taint2 not enabled\n");
        return;
    }
    if (taint2_num_labels_applied() == 0) {
        // see taint_api.cpp, file_taint will take care when to enable taint and all for you!
        // Remember to run pri_taint plugin before file_taint!
        dprintf("[pri_taint] No taint2 num labeled applied\n");
        return;
    }
    dprintf("[pri_taint] OK, Seems like I can Lava Taint! LFG!\n");

    CPUArchState *env = (CPUArchState *) cpu -> env_ptr;
    bool is_strnlen = ((int) buf_len == -1);
    extern ram_addr_t ram_size;
    target_ulong phys = loc_t == LocMem ? panda_virt_to_phys(cpu, buf) : 0;

    if (phys == -1 || phys > ram_size) {
        dprintf("[pri_taint] The physical address is invalid\n");
        return;
    }

    if (debug) {
        printf("Querying \"%s\": " TARGET_FMT_lu " bytes @ 0x%lx phys 0x%lx, strnlen=%d\n", 
                astnodename, buf_len, (unsigned long) buf, (unsigned long) phys, is_strnlen);
        print_membytes(cpu, buf, is_strnlen? 32 : buf_len);
    }

    uint8_t bytes[LAVA_TAINT_QUERY_MAX_LEN] = {0};
    target_ulong len = std::min(buf_len, LAVA_TAINT_QUERY_MAX_LEN);
    if (is_strnlen) {
        panda_physical_memory_read(phys, bytes, LAVA_TAINT_QUERY_MAX_LEN);
        for (uint64_t i = 0; i < LAVA_TAINT_QUERY_MAX_LEN; i++) {
            if (bytes[i] == '\0') {
                len = i;
                break;
            }
        }
        // Only include extent of string (but at least 32 bytes).
        len = std::max((target_ulong)32ULL, len);
    }

    // don't cross page boundaries.
    target_ulong page1 = phys & TARGET_PAGE_MASK;
    target_ulong page2 = (phys + len) & TARGET_PAGE_MASK;
    if (page1 != page2) {
        len = page1 + TARGET_PAGE_SIZE - phys;
        dprintf("[pri_taint] Crossing page boundaries, limiting to %lu\n", (unsigned long) len);
    }

    // okay, taint is on and some labels have actually been applied
    // is there *any* taint on this extent
    uint64_t num_tainted = 0;
    for (uint64_t offset = 0; offset < len; offset++) {
        hwaddr pa = panda_virt_to_phys(cpu, buf + offset);
        if ((int) pa != (hwaddr)-1) {
            ram_addr_t RamOffset = RAM_ADDR_INVALID;
            if (PandaPhysicalAddressToRamOffset(&RamOffset, pa, false) != MEMTX_OK) {
                dprintf("[pri_taint] can't query va=0x%" PRIx64 " pa=0x" TARGET_FMT_plx ": physical map is not RAM.\n", buf + offset, pa);
                continue;
            }
            else {
                Addr a;
                if (loc_t == LocMem) {
                    a = make_maddr(RamOffset);
                }
                else {
                    a = make_greg(buf, offset);
                }
                if (taint2_query(a)) {
                    num_tainted++;
                }
            }
        }
        else {
            dprintf("[pri_taint] Invalid physical address for buf + offset 0x%" PRIx64 "\n", buf + offset);
        }
    }

    // If nothing's tainted and we aren't doing chaff bugs, return.
    if (num_tainted == 0) {
        dprintf("[pri_taint] Nothing is tainted!\n");
        return;
    }

    dprintf("[pri_taint] Starting to write the Panda Log now in pri_taint\n");

    // 1. write the pandalog entry that tells us something was tainted on this extent
    Panda__TaintQueryPri tqh = PANDA__TAINT_QUERY_PRI__INIT;
    tqh.buf = buf;
    tqh.len = len;
    uint32_t data[LAVA_TAINT_QUERY_MAX_LEN] = {0};
    // this is just a snippet.  we dont want to write 1M buffer
    if (loc_t == LocMem) {
        for (int i = 0; i < len; i++) {
            panda_physical_memory_read(phys + i, (uint8_t *)&data[i], 1);
        }
    } else {
        for (uint64_t i = 0; i < len; i++) {
            data[i] = (uint8_t)(env->regs[buf] >> (8 * i));
        }
    }
    tqh.n_data = len;
    tqh.data = data;
    tqh.num_tainted = num_tainted;

    // 2. iterate over the bytes in the extent and pandalog detailed info about taint
    std::vector<Panda__TaintQuery *> tq;
    for (uint32_t offset = 0; offset < len; offset++) {
        hwaddr pa = panda_virt_to_phys(cpu, buf + offset);
        if ((int) pa != (hwaddr) -1) {
            ram_addr_t RamOffset = RAM_ADDR_INVALID;
            if (PandaPhysicalAddressToRamOffset(&RamOffset, pa, false) != MEMTX_OK) {
                dprintf("[pri_taint] can't query va=0x%" PRIx64 " pa=0x%lx: physical map is not RAM.\n",  (uint64_t) buf + offset, pa);
                continue;
            }
            else {
                Addr a;
                if (loc_t == LocMem) {
                    a = make_maddr(RamOffset);
                }
                else {
                    a = make_greg(buf, offset);
                }
                if (taint2_query(a)) {
                    if (loc_t == LocMem) {
                        dprintf("\"%s\" @ 0x" TARGET_FMT_lx " is tainted\n", astnodename, buf + offset);
                    } 
                    else {
                        dprintf("\"%s\" in REG " TARGET_FMT_ld ", byte %d is tainted\n", astnodename, buf, offset);
                    }
                    tq.push_back(taint2_query_pandalog(a, offset));
                }
            }
        }
        else {
            dprintf("[pri_taint] Invalid physical address for buf + offset 0x%" PRIx64 "\n", (uint64_t) buf + offset);
        }
    }

    // 3. write out src-level info
    tqh.src_info = pandalog_src_info_pri_create(global_src_filename, global_src_linenum, astnodename, global_ast_loc_id);

    // 4. write out callstack info
    tqh.call_stack = pandalog_callstack_create();

    dprintf("[pri_taint] num taint queries: %lu\n", tq.size());
    tqh.n_taint_query = tq.size();
    tqh.taint_query = tq.data();
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.taint_query_pri = &tqh;
    pandalog_write_entry(&ple);

    pandalog_callstack_free(tqh.call_stack);
    free(tqh.src_info);
    for (Panda__TaintQuery *ptq : tq) {
        pandalog_taint_query_free(ptq);
    }
}

void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args) {
    if (!taint2_enabled()) {
        dprintf("[pri_taint] Taint2 was not enabled (pfun called)\n");  
        return;
    }

    // Skip these AST node names, they cause issues in bug injection step.
    if (strstr(var_nm, "**") != NULL) {
        dprintf("[pri_taint] Found complex AST expression (contains **): %s\n", var_nm);
        return;
    }

    // lava autogenerated variables start with this string. reg0 and reg1 are registers for hypercall
    const char *blacklist[] = {"kbcieiubweuhc", "phs", "phs_addr", "reg0", "reg1"} ;
    size_t i;
    for (i = 0; i < sizeof(blacklist)/sizeof(blacklist[0]); i++) {
        if (strncmp(var_nm, blacklist[i], strlen(blacklist[i])) == 0) {
            dprintf("[pri_taint] Found a lava generated string: %s\n", var_nm);
            return;
        }
    }

    const char * var_ty = dwarf2_type_to_string((DwarfVarType *) var_ty_void);

    // restore args
    struct args *args = (struct args *) in_args;
    CPUState *pfun_cpu = args->cpu;
    //update global state of src_filename and src_linenum to be used in
    //lava_query in order to create src_info panda log message
    global_src_filename = args->src_filename;
    global_src_linenum = args->src_linenum;
    global_ast_loc_id = args->ast_loc_id;
    // global_funcaddr = args->funcaddr;
    //target_ulong guest_dword;
    //std::string ty_string = std::string(var_ty);
    //size_t num_derefs = std::count(ty_string.begin(), ty_string.end(), '*');
    //size_t i;
    switch (loc_t) {
        // 'dwarf2_type_iter' is defined in dwarf2.cpp
        case LocReg:
            dprintf("[pri_taint] VAR REG:   %s %s in Reg " TARGET_FMT_lu "\n", var_ty, var_nm, loc);
            dwarf2_type_iter(pfun_cpu, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 3);
            break;
        case LocMem:
            dprintf("[pri_taint] VAR MEM:   %s %s @ 0x" TARGET_FMT_lx "\n", var_ty, var_nm, loc);
            dwarf2_type_iter(pfun_cpu, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 3);
            break;
        case LocConst:
            //printf("VAR CONST: %s %s as 0x%x\n", var_ty, var_nm, loc);
            break;
        case LocErr:
            //printf("VAR does not have a location we could determine. Most likely because the var is split among multiple locations\n");
            break;
        // should not get here
        default:
            assert(1==0);
    }
}

void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, 
                    const char *funct_name, unsigned long long lno) {
    if (taint2_enabled()) {
        struct args args = {cpu, file_Name, lno, 0};
        dprintf("[%s] %s(), ln: %4lld, pc @ 0x%lx\n", file_Name, funct_name, lno, (unsigned long) pc);
        pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
    }
}

// Taken from taint2_hypercalls.cpp, not sure why but at the moment
// AttackPoints is never populated.
Panda__SrcInfo *pandalog_src_info_create(PandaHypercallStruct phs) {
    Panda__SrcInfo *si = (Panda__SrcInfo *) malloc(sizeof(Panda__SrcInfo));
    *si = PANDA__SRC_INFO__INIT;
    si->filename = phs.src_filename;
    si->astnodename = phs.src_ast_node_name;
    si->linenum = phs.src_linenum;
    si->has_insertionpoint = 0;
    if (phs.insertion_point) {
        si->has_insertionpoint = 1;
        si->insertionpoint = phs.insertion_point;
    }
    si->has_ast_loc_id = 1;
    si->ast_loc_id = phs.src_filename;
    return si;
}

void lava_attack_point(PandaHypercallStruct phs) {
    if (pandalog) {
        Panda__AttackPoint *ap = (Panda__AttackPoint *)malloc(sizeof(Panda__AttackPoint));
        *ap = PANDA__ATTACK_POINT__INIT;
        ap->info = phs.info;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.attack_point = ap;
        ple.attack_point->src_info = pandalog_src_info_create(phs);
        ple.attack_point->call_stack = pandalog_callstack_create();
        pandalog_write_entry(&ple);
        free(ple.attack_point->src_info);
        pandalog_callstack_free(ple.attack_point->call_stack);
        free(ap);
    }
}

/*
// Trace logging in the level of source code
void hypercall_log_trace(unsigned ast_loc_id) {
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    Panda__SourceTraceId stid = PANDA__SOURCE_TRACE_ID__INIT;
    stid.ast_loc_id = ast_loc_id;
    ple.source_trace_id = &stid;
    pandalog_write_entry(&ple);
}
*/

// Support all features of label and query program
void lava_hypercall(CPUState *cpu) {
    dprintf("[pri_taint] Calling lava hypercall!\n");
    CPUArchState *env = (CPUArchState*) cpu->env_ptr;
    if (taint2_enabled()) {
        // LAVA Hypercall
        #if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
            target_ulong addr = panda_virt_to_phys(cpu, env->regs[0]);
        #elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
            target_ulong addr = panda_virt_to_phys(cpu, env->xregs[0]);
        #elif defined(TARGET_I386) && !defined(TARGET_X86_64)
            target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EBX]);
        #elif defined(TARGET_I386) && defined(TARGET_X86_64)
            target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EDI]);
        #endif

        if ((int) addr == -1) {
            #if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
                dprintf("[pri_taint] panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%x paddr=0x%x\n",
                    (uint32_t) env->regs[0], (uint32_t) addr);
            #elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
                dprintf("[pri_taint] panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%lx paddr=0x%lx\n",
                    (uint64_t) env->xregs[0], (uint64_t) addr);
            #elif defined(TARGET_I386) && !defined(TARGET_X86_64)
                dprintf("[pri_taint] panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%x paddr=0x%x\n",
                    (uint32_t) env->regs[R_EBX], (uint32_t) addr);
            #elif defined(TARGET_I386) && defined(TARGET_X86_64)
                dprintf("[pri_taint] panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%lx paddr=0x%lx\n",
                    (uint64_t) env->regs[R_EDI], (uint64_t) addr);
            #endif
        }
        else if (pandalog) {
            dprintf("[pri_taint] Hypercall is OK and Panda Log is set\n");  
            PandaHypercallStruct phs;
            #if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
                panda_virtual_memory_read(cpu, env->regs[0], (uint8_t *) &phs, sizeof(phs));
            #elif defined(TARGET_ARM) && defined(TARGET_AARCH64)
                panda_virtual_memory_read(cpu, env->xregs[0], (uint8_t *) &phs, sizeof(phs));
            #elif defined(TARGET_I386) && !defined(TARGET_X86_64)
                panda_virtual_memory_read(cpu, env->regs[R_EBX], (uint8_t *) &phs, sizeof(phs));
            #elif defined(TARGET_I386) && defined(TARGET_X86_64)
                panda_virtual_memory_read(cpu, env->regs[R_EDI], (uint8_t *) &phs, sizeof(phs));
            #endif

            // To be used for chaff bugs?
            // uint64_t funcaddr = 0;
            // panda_virtual_memory_read(cpu, phs.info, (uint8_t*)&funcaddr, sizeof(target_ulong));
            // if the phs action is a pri_query point, see
            // lava/include/pirate_mark_lava.h
            if (phs.action == 13) {
                target_ulong pc = panda_current_pc(cpu);
                // Calls 'pri_get_pc_source_info' in pri.c, which calls 'on_get_pc_source_info'
                // In Dwarf2, the function 'on_get_pc_source_info' is mapped to 'dwarf_get_pc_source_info'
                SrcInfo info;
                int rc = pri_get_pc_source_info(cpu, pc, &info);
                if (!rc) {
                    struct args args = {cpu, info.filename, info.line_number, phs.src_filename};
                    dprintf("[pri_taint] panda hypercall: [%s], "
                            "ln: %4ld, pc @ 0x" TARGET_FMT_lx "\n",
                            info.filename,
                            info.line_number, pc);
                    // Calls 'pri_funct_livevar_iter' in pri.c, which calls 'on_funct_livevar_iter'
                    // In Dwarf2, the function 'on_funct_livevar_iter' is mapped to 'dwarf_funct_livevar_iter'
                    // This is passing the function 'pfun' to 'pri_funct_livevar_iter', which is called at the end
                    pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
                }
                else {
                    dprintf("[pri_taint] pri_get_pc_src_info has failed: %d != 0.\n", rc);
                }
                // hypercall_log_trace(phs.src_filename);
            }
            else if (phs.action == 12) {
                lava_attack_point(phs);
            }
            else {
                dprintf("[pri_taint] Invalid action value in PHS struct: %d != 12/13.\n", phs.action);  
            } 
        }
        else {
            dprintf("[pri_taint] No Panda Log even though hypercall seemed OK!\n");
        }
    }
    else {
        dprintf("[pri_taint] taint2 is not enabled (hypercall)\n");
    }
}
#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386) || defined(TARGET_ARM)
    panda_arg_list *args = panda_get_args("pri_taint");
    hypercall_taint = panda_parse_bool_opt(args, "hypercall", "Register tainting on a panda hypercall callback");
    linechange_taint = panda_parse_bool_opt(args, "linechange", "Register tainting on every line change in the source code (default)");
    // TODO: Future PR, we will aim to integrate LAVA to support chaff bugs and real bugs
    // chaff_bugs = panda_parse_bool_opt(args, "chaff", "Record untainted extents for chaff bugs.");
    debug = panda_parse_bool_opt(args, "debug", "enable debug output");
    // default linechange_taint to true if there is no hypercall taint
    if (!hypercall_taint) {
        linechange_taint = true;
    }

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    panda_require("pri");
    assert(init_pri_api());
    panda_require("dwarf2");
    assert(init_dwarf2_api());
    panda_require("taint2");
    assert(init_taint2_api());

    if (hypercall_taint) {
        panda_require("hypercaller");
        void * hypercaller = panda_get_plugin_by_name("hypercaller");
        register_hypercall_t register_hypercall = (register_hypercall_t) dlsym(hypercaller, "register_hypercall");
        register_hypercall(LAVA_MAGIC, lava_hypercall);
    }
    if (linechange_taint) {
        PPP_REG_CB("pri", on_before_line_change, on_line_change);
    }

    printf("[pri_taint] This plugin is activated!\n");
    return true;
#else
    printf("[pri_taint] This plugin is only supported on x86 or ARM\n");
    return false;
#endif
}

void uninit_plugin(void *self) {
    // You don't need to unregister the hypercall!
    printf("[pri_taint] Unloading plugin complete!\n");
}

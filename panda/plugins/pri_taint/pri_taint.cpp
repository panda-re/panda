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

extern "C" {

#include "panda/rr/rr_log.h"
#include "panda/addr.h"
#include "panda/plog.h"

#include "taint2/taint2_hypercalls.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

// needed for accessing type information on linux/elf based systems
#include "pri_dwarf/pri_dwarf_types.h"
#include "pri_dwarf/pri_dwarf_ext.h"

#include "callstack_instr/callstack_instr_ext.h"

// taint
#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel() ;
void set_loglevel(int new_loglevel);
}
bool linechange_taint = true;
bool hypercall_taint = true;
bool chaff_bugs = false;
Panda__SrcInfoPri *si = NULL;
const char *global_src_filename = NULL;
uint64_t global_src_linenum;
unsigned global_ast_loc_id;
bool debug = false;

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
// should just be able to include these from taint2.h or taint_processor.cpp
Addr make_maddr(uint64_t a) {
  Addr ma;
  ma.typ = MADDR;
  ma.val.ma = a;
  ma.off = 0;
  ma.flag = (AddrFlag) 0;
  return ma;
}
Addr make_greg(uint64_t r, uint16_t off) {
    Addr ra = {
        .typ = GREG,
        .val = { .gr = r },
        .off = off,
        .flag = (AddrFlag) 0
    };
    return ra;
}
void print_membytes(CPUState *env, target_ulong a, target_ulong len) {
    unsigned char c;
    printf("{ ");
    for (int i = 0; i < len; i++) {
        if (-1 == panda_virtual_memory_read(env, a+i, (uint8_t *) &c, sizeof(char))) {
            printf(" XX");
        } else {
            printf("%02x ", c);
        }
    }
    printf("}");
}

// max length of strnlen or taint query
#define LAVA_TAINT_QUERY_MAX_LEN 64U
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void lava_taint_query(target_ulong buf, LocType loc_t, target_ulong buf_len, const char *astnodename) {
    // can't do a taint query if it is not a valid register (loc) or if
    // the buf_len is greater than the register size (assume size of guest pointer)
    if (loc_t == LocReg && (buf >= CPU_NB_REGS || buf_len >= sizeof(target_ulong) ||
                buf_len == (target_ulong)-1))
        return;
    if (loc_t == LocErr || loc_t == LocConst)
        return;
    if (!pandalog || !taint2_enabled() || taint2_num_labels_applied() == 0)
        return;

    CPUState *cpu = first_cpu;
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    bool is_strnlen = ((int) buf_len == -1);
    extern ram_addr_t ram_size;
    target_ulong phys = loc_t == LocMem ? panda_virt_to_phys(cpu, buf) : 0;

    if (phys == -1 || phys > ram_size) return;

    if (debug) {
        printf("Querying \"%s\": " TARGET_FMT_lu " bytes @ 0x" TARGET_FMT_lx " phys 0x" TARGET_FMT_lx ", strnlen=%d", astnodename, buf_len, buf, phys, is_strnlen);
        print_membytes(cpu, buf, is_strnlen? 32 : buf_len);
        printf("\n");
    }

    uint8_t bytes[LAVA_TAINT_QUERY_MAX_LEN] = {0};
    uint32_t len = std::min(buf_len, LAVA_TAINT_QUERY_MAX_LEN);
    if (is_strnlen) {
        panda_physical_memory_rw(phys, bytes, LAVA_TAINT_QUERY_MAX_LEN, false);
        for (int i = 0; i < LAVA_TAINT_QUERY_MAX_LEN; i++) {
            if (bytes[i] == '\0') {
                len = i;
                break;
            }
        }
        // Only include extent of string (but at least 32 bytes).
        len = std::max(32U, len);
    }

    // don't cross page boundaries.
    target_ulong page1 = phys & TARGET_PAGE_MASK;
    target_ulong page2 = (phys + len) & TARGET_PAGE_MASK;
    if (page1 != page2) {
        len = page1 + TARGET_PAGE_SIZE - phys;
    }

    // okay, taint is on and some labels have actually been applied
    // is there *any* taint on this extent
    uint32_t num_tainted = 0;
    for (uint32_t i = 0; i < len; i++) {
        Addr a = loc_t == LocMem ? make_maddr(phys + i) : make_greg(buf, i);
        if (taint2_query(a)) num_tainted++;
    }

    // If nothing's tainted and we aren't doing chaff bugs, return.
    if (!chaff_bugs && num_tainted == 0) return;

    // 1. write the pandalog entry that tells us something was tainted on this extent
    Panda__TaintQueryPri tqh = PANDA__TAINT_QUERY_PRI__INIT;
    tqh.buf = buf;
    tqh.len = len;
    uint32_t data[LAVA_TAINT_QUERY_MAX_LEN] = {0};
    // this is just a snippet.  we dont want to write 1M buffer
    if (loc_t == LocMem) {
        for (int i = 0; i < len; i++) {
            panda_physical_memory_rw(phys + i, (uint8_t *)&data[i], 1, false);
        }
    } else {
        for (int i = 0; i < len; i++) {
            data[i] = (uint8_t)(env->regs[buf] >> (8 * i));
        }
    }
    tqh.n_data = len;
    tqh.data = data;
    tqh.num_tainted = num_tainted;

    // 2. iterate over the bytes in the extent and pandalog detailed info about taint
    std::vector<Panda__TaintQuery *> tq;
    for (uint32_t offset = 0; offset < len; offset++) {
        uint32_t pa_indexed = phys + offset;
        Addr a = loc_t == LocMem ? make_maddr(pa_indexed) : make_greg(buf, offset);
        if (taint2_query(a)) {
            if (loc_t == LocMem) {
                dprintf("\"%s\" @ 0x%x is tainted\n", astnodename, buf + offset);
            } else {
                dprintf("\"%s\" in REG " TARGET_FMT_ld ", byte %d is tainted\n", astnodename, buf, offset);
            }
            tq.push_back(taint2_query_pandalog(a, offset));
        }
    }

    // 3. write out src-level info
    tqh.src_info = pandalog_src_info_pri_create(global_src_filename,
            global_src_linenum, astnodename, global_ast_loc_id);

    // 4. write out callstack info
    tqh.call_stack = pandalog_callstack_create();

    dprintf("num taint queries: %lu\n", tq.size());
    tqh.n_taint_query = tq.size();
    tqh.taint_query = tq.data();
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.taint_query_pri = &tqh;
    pandalog_write_entry(&ple);

    pandalog_callstack_free(tqh.call_stack);
    free(tqh.src_info);
    for (Panda__TaintQuery *ptq : tq) pandalog_taint_query_free(ptq);
}
#endif
struct args {
    CPUState *cpu;
    const char *src_filename;
    uint64_t src_linenum;
    unsigned ast_loc_id;
};

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
    if (!taint2_enabled())
        return;
    // lava autogenerated variables start with this string
    const char *blacklist[] = {"kbcieiubweuhc", "phs", "phs_addr"} ;
    size_t i;
    for (i = 0; i < sizeof(blacklist)/sizeof(blacklist[0]); i++) {
        if (strncmp(var_nm, blacklist[i], strlen(blacklist[i])) == 0) {
            //printf(" Found a lava generated string: %s", var_nm);
            return;
        }
    }
    const char *var_ty = dwarf_type_to_string((DwarfVarType *) var_ty_void);
    // restore args
    struct args *args = (struct args *) in_args;
    CPUState *pfun_cpu = args->cpu;
    //update global state of src_filename and src_linenum to be used in
    //lava_query in order to create src_info panda log message
    global_src_filename = args->src_filename;
    global_src_linenum = args->src_linenum;
    global_ast_loc_id = args->ast_loc_id;
    //target_ulong guest_dword;
    //std::string ty_string = std::string(var_ty);
    //size_t num_derefs = std::count(ty_string.begin(), ty_string.end(), '*');
    //size_t i;
    switch (loc_t){
        case LocReg:
            dprintf("VAR REG:   %s %s in Reg %d\n", var_ty, var_nm, loc);
            dwarf_type_iter(pfun_cpu, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 3);
            break;
        case LocMem:
            if (debug)
                printf("VAR MEM:   %s %s @ 0x" TARGET_FMT_lx "\n", var_ty, var_nm, loc);
            dwarf_type_iter(pfun_cpu, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 3);
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
    free(si);
}

void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    if (taint2_enabled()){
        struct args args = {cpu, file_Name, lno, 0};
        //printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
        pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
        //pri_all_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
    }
}
void on_fn_start(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    struct args args = {cpu, file_Name, lno, 0};
    dprintf("fn-start: %s() [%s], ln: %4lld, pc @ 0x%x\n",funct_name,file_Name,lno,pc);
    pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
}

#ifdef TARGET_I386
// Support all features of label and query program
void i386_hypercall_callback(CPUState *cpu){
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if (taint2_enabled() && pandalog) {
        // LAVA Hypercall
        target_ulong addr = panda_virt_to_phys(cpu, env->regs[R_EAX]);
        if ((int)addr == -1) {
            printf ("panda hypercall with ptr to invalid PandaHypercallStruct: vaddr=0x%x paddr=0x%x\n",
                    (uint32_t) env->regs[R_EAX], (uint32_t) addr);
        }
        else {
            PandaHypercallStruct phs;
            panda_virtual_memory_rw(cpu, env->regs[R_EAX], (uint8_t *) &phs, sizeof(phs), false);
            if (phs.magic == 0xabcd) {
                // if the phs action is a pri_query point, see
                // lava/include/pirate_mark_lava.h
                if (phs.action == 13) {
                    target_ulong pc = panda_current_pc(cpu);
                    SrcInfo info;
                    int rc = pri_get_pc_source_info(cpu, pc, &info);
                    if (!rc) {
                        struct args args = {cpu, info.filename, info.line_number, phs.src_filename};
                        dprintf("panda hypercall: [%s], "
                                "ln: %4ld, pc @ 0x" TARGET_FMT_lx "\n",
                                info.filename,
                                info.line_number,pc);
                        pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
                        //pri_all_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *)&args);
                        //lava_attack_point(phs);
                    }
                }
            }
            else {
                printf ("Invalid magic value in PHS struct: %x != 0xabcd.\n", phs.magic);
            }
        }
    }
}
#endif // TARGET_I386


int guest_hypercall_callback(CPUState *cpu){
#ifdef TARGET_I386
    i386_hypercall_callback(cpu);
#endif

#ifdef TARGET_ARM
    // not implemented for now
    //arm_hypercall_callback(cpu);
#endif

    return 1;
}
#endif
/*
void on_taint_change(Addr a, uint64_t size){
    uint32_t num_tainted = 0;
    for (uint32_t i=0; i<size; i++){
        a.off = i;
        num_tainted += (taint2_query(a) != 0);
    }
    if (num_tainted > 0) {
        printf("In taint change!\n");
    }
}
*/
bool init_plugin(void *self) {

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    panda_arg_list *args = panda_get_args("pri_taint");
    hypercall_taint = panda_parse_bool_opt(args, "hypercall", "Register tainting on a panda hypercall callback");
    linechange_taint = panda_parse_bool_opt(args, "linechange", "Register tainting on every line change in the source code (default)");
    chaff_bugs = panda_parse_bool_opt(args, "chaff", "Record untainted extents for chaff bugs.");
    // default linechange_taint to true if there is no hypercall taint
    if (!hypercall_taint)
        linechange_taint = true;
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    panda_require("pri");
    assert(init_pri_api());
    panda_require("pri_dwarf");
    assert(init_pri_dwarf_api());

    panda_require("taint2");
    assert(init_taint2_api());

    if (hypercall_taint) {
        panda_cb pcb;
        pcb.guest_hypercall = guest_hypercall_callback;
        panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);
    }
    if (linechange_taint){
        PPP_REG_CB("pri", on_before_line_change, on_line_change);
    }
    //taint2_track_taint_state();
#endif
    return true;
}



void uninit_plugin(void *self) {
}


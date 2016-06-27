#define __STDC_FORMAT_MACROS

// taint
#include "../taint2/label_set.h"
#include "../taint2/taint2.h"
#include "../common/prog_point.h"

#include <algorithm>

extern "C" {

#include <stdlib.h>

#include "panda/panda_addr.h"
#include "rr_log.h"
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "pandalog.h"
#include "panda_common.h"

#include "../pri/pri_types.h"
#include "../pri/pri_ext.h"
#include "../pri/pri.h"

// needed for accessing type information on linux/elf based systems
#include "../pri_dwarf/pri_dwarf_types.h"
#include "../pri_dwarf/pri_dwarf_ext.h"

// taint
#include "../taint2/taint2_ext.h"

// needed for callstack logging
#include "../callstack_instr/callstack_instr_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel() ;
void set_loglevel(int new_loglevel);
}
Panda__SrcInfoPri *si = NULL;
const char *global_src_filename = NULL;
uint64_t global_src_linenum;

Panda__SrcInfoPri *pandalog_src_info_pri_create(const char *src_filename, uint64_t src_linenum, const char *src_ast_node_name) {
    Panda__SrcInfoPri *si = (Panda__SrcInfoPri *) malloc(sizeof(Panda__SrcInfoPri));
    *si = PANDA__SRC_INFO_PRI__INIT;

    si->filename = (char *) src_filename;
    si->astnodename = (char *) src_ast_node_name;
    si->linenum = src_linenum;

    si->has_insertionpoint = 1;
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

// max length of strnlen or taint query
#define LAVA_TAINT_QUERY_MAX_LEN 32
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void lava_taint_query ( target_ulong buf, LocType loc_t, target_ulong buf_len, const char *astnodename) {
    // can't do a taint query if it is not a valid register (loc) or if
    // the buf_len is greater than the register size (assume size of guest pointer)
    if (loc_t == LocReg && (buf >= CPU_NB_REGS || buf_len >= sizeof(target_ulong) ||
                buf_len == (target_ulong)-1))
        return;
    if (loc_t == LocErr || loc_t == LocConst)
        return;
    extern CPUState *cpu_single_env;
    CPUState *env = cpu_single_env;
    bool is_strnlen = ((int) buf_len == -1);
    if (is_strnlen){
        //printf("Querying char* @ 0x" TARGET_FMT_lx "\n", buf);
    }
    else{
        //printf("Querying " TARGET_FMT_lu " bytes @ 0x" TARGET_FMT_lx ", strnlen=false\n", buf_len, buf);

    }
    //if  (pandalog && taintEnabled && (taint2_num_labels_applied() > 0)){
    if  (pandalog && taint2_enabled() && (taint2_num_labels_applied() > 0)){
        // okay, taint is on and some labels have actually been applied
        // is there *any* taint on this extent
        uint32_t num_tainted = 0;
        uint32_t offset=0;
        while (true) {
        //        for (uint32_t offset=0; offset<phs.len; offset++) {
            uint32_t va = buf + offset;
            //uint32_t va = phs.buf + offset;
            uint32_t pa = loc_t == LocMem ? panda_virt_to_phys(env, va) : 0;
            if (is_strnlen) {
                uint8_t c;
                panda_virtual_memory_rw(env, pa, &c, 1, false);
                // null terminator
                if (c==0) break;
            }
            if ((int) pa != -1) {
                Addr a = loc_t == LocMem ? make_maddr(pa) : make_greg(buf, offset);
                if (taint2_query(a)) {
                    if (loc_t == LocMem) { 
                        printf("\"%s\" @ 0x%x is tainted\n", astnodename, va);
                    }
                    else {
                        printf("\"%s\" in REG " TARGET_FMT_ld ", byte %d is tainted\n", astnodename, buf, offset);
                    }
                    num_tainted ++;
                }
            }
            offset ++;
            // end of query by length or max string length
            if (!is_strnlen && offset == buf_len) break;
            //if (!is_strnlen && offset == phs.len) break;
            if (is_strnlen && (offset == LAVA_TAINT_QUERY_MAX_LEN)) break;
        }
        uint32_t len = offset;
        if (num_tainted) {
            // ok at least one byte in the extent is tainted
            // 1. write the pandalog entry that tells us something was tainted on this extent
            Panda__TaintQueryPri *tqh = (Panda__TaintQueryPri *) malloc (sizeof (Panda__TaintQueryPri));
            *tqh = PANDA__TAINT_QUERY_PRI__INIT;
            tqh->buf = buf;
            tqh->len = len;
            tqh->num_tainted = num_tainted;
            // obtain the actual data out of memory
            // NOTE: first X bytes only!
            uint32_t data[LAVA_TAINT_QUERY_MAX_LEN];
            uint32_t n = len;
            // grab at most X bytes from memory to pandalog
            // this is just a snippet.  we dont want to write 1M buffer
            if (LAVA_TAINT_QUERY_MAX_LEN < len) 
                n = LAVA_TAINT_QUERY_MAX_LEN;
            for (uint32_t i=0; i<n; i++) {
                data[i] = 0;
                uint8_t c;
                if (loc_t == LocMem) {
                    panda_virtual_memory_rw(env, buf+i, &c, 1, false);
                }
                else {
                    c = ((0xff << i*8) && env->regs[buf]) >> i*8;
                }
                data[i] = c;
            }
            tqh->n_data = n;
            tqh->data = data;
            // 2. write out src-level info
            // si is global variable that is updated whenever location in source changes
            tqh->src_info=pandalog_src_info_pri_create(global_src_filename,global_src_linenum, astnodename);
            // 3. write out callstack info
            Panda__CallStack *cs = pandalog_callstack_create();
            tqh->call_stack = cs;
            // 4. iterate over the bytes in the extent and pandalog detailed info about taint
            std::vector<Panda__TaintQuery *> tq;
            for (uint32_t offset=0; offset<len; offset++) {
                uint32_t va = buf + offset;
                //uint32_t va = phs.buf + offset;
                uint32_t pa = loc_t == LocMem ? panda_virt_to_phys(env, va) : 0;
                if ((int) pa != -1) {
                    Addr a = loc_t == LocMem ? make_maddr(pa) : make_greg(buf, offset);
                    if (taint2_query(a)) {
                        tq.push_back(taint2_query_pandalog(a, offset));
                    }
                }
            }
            printf("num taint queries: %lu\n", tq.size());
            tqh->n_taint_query = tq.size();
            tqh->taint_query = (Panda__TaintQuery **) malloc(sizeof(Panda__TaintQuery *) * tqh->n_taint_query);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                tqh->taint_query[i] = tq[i];
            }
            Panda__LogEntry ple;
            ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_query_pri = tqh;
            pandalog_write_entry(&ple);
            // can't free this here because src_info will be used by other
            // variables
            free(tqh->src_info);
            pandalog_callstack_free(tqh->call_stack);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                pandalog_taint_query_free(tqh->taint_query[i]);
            }
            free(tqh);
        }
    }
}
#endif
struct args {
    CPUState *env;
    const char *src_filename;
    uint64_t src_linenum;
};

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
    if (!taint2_enabled())
        return;
    const char *var_ty = dwarf_type_to_string((DwarfVarType *) var_ty_void);
    // restore args
    struct args *args = (struct args *) in_args;
    CPUState *pfun_env = args->env;
    //update global state of src_filename and src_linenum to be used in
    //lava_query in order to create src_info panda log message
    global_src_filename = args->src_filename;
    global_src_linenum = args->src_linenum;
    //target_ulong guest_dword;
    //std::string ty_string = std::string(var_ty);
    //size_t num_derefs = std::count(ty_string.begin(), ty_string.end(), '*');
    //size_t i;
    switch (loc_t){
        case LocReg:
            printf("VAR REG:   %s %s in Reg %d\n", var_ty, var_nm, loc);
            dwarf_type_iter(pfun_env, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 2);
            break;
        case LocMem:
            //printf("VAR MEM:   %s %s @ 0x" TARGET_FMT_lx "\n", var_ty, var_nm, loc);
            dwarf_type_iter(pfun_env, loc, loc_t, (DwarfVarType *) var_ty_void, lava_taint_query, 2);
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

void on_line_change(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    if (taint2_enabled()){
        struct args args = {env, file_Name, lno};
        //printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
        //pri_funct_livevar_iter(env, pc, (liveVarCB) pfun, (void *)&args);
        pri_all_livevar_iter(env, pc, (liveVarCB) pfun, (void *)&args);
    }
}
void on_fn_start(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    struct args args = {env, file_Name, lno};
    printf("fn-start: %s() [%s], ln: %4lld, pc @ 0x%x\n",funct_name,file_Name,lno,pc);
    pri_funct_livevar_iter(env, pc, (liveVarCB) pfun, (void *)&args);
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
    //printf("Initializing plugin dwarf_taint\n");
    //panda_arg_list *args = panda_get_args("dwarf_taint");
    panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    panda_require("pri");
    assert(init_pri_api());
    panda_require("pri_dwarf");
    assert(init_pri_dwarf_api());

    panda_require("taint2");
    assert(init_taint2_api());
    //assert(init_file_taint_api());

    PPP_REG_CB("pri", on_before_line_change, on_line_change);
    //PPP_REG_CB("pri", on_fn_start, on_fn_start);
    //PPP_REG_CB("taint2", on_taint_change, on_taint_change);
    //taint2_track_taint_state();
#endif
    return true;
}



void uninit_plugin(void *self) {
}


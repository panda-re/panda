#define __STDC_FORMAT_MACROS

// taint
#include "../taint2/label_set.h"
#include "../taint2/taint2.h"
#include "../common/prog_point.h"

#include <algorithm>

extern "C" {

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


// taint
#include "../taint2/taint2_ext.h"

// needed for callstack logging
#include "../callstack_instr/callstack_instr_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel() ;
void set_loglevel(int new_loglevel);
}

Panda__SrcInfoPri *pandalog_src_info_pri_create(const char *src_filename, uint64_t src_linenum, const char *src_ast_node_name) {
    Panda__SrcInfoPri *si = (Panda__SrcInfoPri *) malloc(sizeof(Panda__SrcInfoPri));
    *si = PANDA__SRC_INFO_PRI__INIT;

    si->filename = (char *) src_filename;
    si->astnodename = (char *) src_ast_node_name;
    si->linenum = src_linenum;

    si->has_insertionpoint = 1;
    si->insertionpoint = src_linenum - 1;
    return si;
}
// should just be able to include this from taint2.h but not able to, so just copied the function
Addr make_maddr(uint64_t a) {
  Addr ma;
  ma.typ = MADDR;
  ma.val.ma = a;
  ma.off = 0;
  ma.flag = (AddrFlag) 0;
  return ma;
}
// max length of strnlen or taint query
#define LAVA_TAINT_QUERY_MAX_LEN 32
// hypercall-initiated taint query of some src-level extent
void lava_taint_query (Panda__SrcInfoPri *si, target_ulong buf, target_ulong buf_len) {
    extern CPUState *cpu_single_env;
    CPUState *env = cpu_single_env;

    //if  (pandalog && taintEnabled && (taint2_num_labels_applied() > 0)){
    if  (pandalog && taint2_enabled() && (taint2_num_labels_applied() > 0)){
        // okay, taint is on and some labels have actually been applied
        // is there *any* taint on this extent
        uint32_t num_tainted = 0;
        bool is_strnlen = false;
        //bool is_strnlen = ((int) phs.len == -1);
        uint32_t offset=0;
        while (true) {
        //        for (uint32_t offset=0; offset<phs.len; offset++) {
            uint32_t va = buf + offset;
            //uint32_t va = phs.buf + offset;
            uint32_t pa =  panda_virt_to_phys(env, va);
            if (is_strnlen) {
                uint8_t c;
                panda_virtual_memory_rw(env, pa, &c, 1, false);
                // null terminator
                if (c==0) break;
            }
            if ((int) pa != -1) {
                Addr a = make_maddr(pa);
                if (taint2_query(a)) {
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
            printf("logging lava query\n");
            // ok at least one byte in the extent is tainted
            // 1. write the pandalog entry that tells us something was tainted on this extent
            Panda__TaintQueryPri *tqh = (Panda__TaintQueryPri *) malloc (sizeof (Panda__TaintQueryPri));
            *tqh = PANDA__TAINT_QUERY_PRI__INIT;
            tqh->buf = buf;
            //tqh->buf = phs.buf;
            tqh->len = len;
            tqh->num_tainted = num_tainted;
            // obtain the actual data out of memory
            // NOTE: first X bytes only!
            uint32_t data[LAVA_TAINT_QUERY_MAX_LEN];
            uint32_t n = len;
            // grab at most X bytes from memory to pandalog
            // this is just a snippet.  we dont want to write 1M buffer
            if (LAVA_TAINT_QUERY_MAX_LEN < len) n = LAVA_TAINT_QUERY_MAX_LEN;
            for (uint32_t i=0; i<n; i++) {
                data[i] = 0;
                uint8_t c;
                panda_virtual_memory_rw(env, buf+i, &c, 1, false);
                //panda_virtual_memory_rw(env, phs.buf+i, &c, 1, false);
                data[i] = c;
            }
            tqh->n_data = n;
            tqh->data = data;
            // 2. write out src-level info
            //Panda__SrcInfoPri *si = pandalog_src_info_create(phs);
            tqh->src_info = si;
            // 3. write out callstack info
            Panda__CallStack *cs = pandalog_callstack_create();
            tqh->call_stack = cs;
            // 4. iterate over the bytes in the extent and pandalog detailed info about taint
            std::vector<Panda__TaintQuery *> tq;
            for (uint32_t offset=0; offset<len; offset++) {
                uint32_t va = buf + offset;
                //uint32_t va = phs.buf + offset;
                uint32_t pa =  panda_virt_to_phys(env, va);
                if ((int) pa != -1) {
                    Addr a = make_maddr(pa);
                    if (taint2_query(a)) {
                        tq.push_back(taint2_query_pandalog(a, offset));
                    }
                }
            }
            tqh->n_taint_query = tq.size();
            tqh->taint_query = (Panda__TaintQuery **) malloc(sizeof(Panda__TaintQuery *) * tqh->n_taint_query);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                tqh->taint_query[i] = tq[i];
            }
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_query_pri = tqh;
            printf("about to write out taint query entry\n");
            pandalog_write_entry(&ple);
            free(tqh->src_info);
            pandalog_callstack_free(tqh->call_stack);
            for (uint32_t i=0; i<tqh->n_taint_query; i++) {
                pandalog_taint_query_free(tqh->taint_query[i]);
            }
            free(tqh);
        }
    }
}
struct args {
    CPUState *env;
    const char *src_filename;
    uint64_t src_linenum;
};

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
//void pfun(const char *var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
    // restore args
    const char *var_ty = (const char *) var_ty_void;
    struct args *args = (struct args *) in_args;
    CPUState *pfun_env = args->env;
    const char *src_filename = args->src_filename;
    uint64_t src_linenum = args->src_linenum;

    target_ulong guest_dword;
    std::string ty_string = std::string(var_ty);
    size_t num_derefs = std::count(ty_string.begin(), ty_string.end(), '*');
    size_t i;
    //Panda__SrcInfoPri *si = pandalog_src_info_pri_create(const char *src_filename, uint64_t src_linenum, const char *src_ast_node_name);
    Panda__SrcInfoPri *si = pandalog_src_info_pri_create(src_filename, src_linenum, var_nm);
    switch (loc_t){
        case LocReg:
            guest_dword = pfun_env->regs[loc];
            if (num_derefs > 0) {
                for (i = 0; i < num_derefs; i++) {
                    int rc = panda_virtual_memory_rw(pfun_env, guest_dword, (uint8_t *)&guest_dword, sizeof(guest_dword), 0);
                    if (0 != rc)
                        break;
                }
                if (0 != taint2_query_ram(panda_virt_to_phys(pfun_env, guest_dword)))  {
                    printf("VAR REG:   %s %s in Reg %d\n", var_ty, var_nm, loc);
                    printf("    => 0x%x, derefs: %ld\n", guest_dword, i);
                    printf(" ==Location is tainted!==\n");
                    lava_taint_query(si, guest_dword, 1);
                }
            }
            else {
                // only query reg taint if the reg number is less than the number of registers
                if (loc < CPU_NB_REGS) {
                    if (0 != taint2_query_reg(loc, 0)) {
                        printf("VAR REG:   %s %s in Reg %d\n", var_ty, var_nm, loc);
                        printf("    => 0x%x, derefs: %d\n", guest_dword, 0);
                        printf(" ==Reg is tainted!==\n");
                    }
                }
            }

            break;
        case LocMem:
            guest_dword = loc;
            for (i = 0; i < num_derefs; i++) {
                if (0 != panda_virtual_memory_rw(pfun_env, guest_dword, (uint8_t *)&guest_dword, sizeof(guest_dword), 0)){
                    break;
                }
            }
            if (0 != taint2_query_ram(panda_virt_to_phys(pfun_env, guest_dword)))  {
                printf("VAR MEM:   %s %s @ 0x%x\n", var_ty, var_nm, loc);
                printf("    => 0x%x, derefs: %ld\n", guest_dword, i);
                printf(" ==Location is tainted!==\n");
                lava_taint_query(si, guest_dword, 1);
            }
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

void on_line_change(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    struct args args = {env, file_Name, lno};
    printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
    pri_funct_livevar_iter(env, pc, (liveVarCB) pfun, (void *)&args);
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
    //panda_require("pri_dwarf");
    //assert(init_pri_dwarf_api());
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


#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

#include "panda/rr/rr_log.h"
#include "panda/addr.h"
#include "panda/plog.h"

#include "pri/pri_types.h"
#include "pri/pri_ext.h"
#include "pri/pri.h"

#include "pri_dwarf/pri_dwarf_types.h"
#include "pri_dwarf/pri_dwarf_ext.h"

    bool init_plugin(void *);
    void uninit_plugin(void *);

    int get_loglevel() ;
    void set_loglevel(int new_loglevel);

    //void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno);
}
struct args {
    CPUState *cpu;
    const char *src_filename;
    uint64_t src_linenum;
};
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
//void pfun(VarType var_ty, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
void pfun(void *var_ty_void, const char *var_nm, LocType loc_t, target_ulong loc, void *in_args){
    const char *var_ty = dwarf_type_to_string((DwarfVarType *) var_ty_void);
    //const char *var_ty = "";
    // restore args
    struct args *args = (struct args *) in_args;
    CPUState *pfun_cpu = args->cpu;
    CPUArchState *pfun_env = (CPUArchState*)pfun_cpu->env_ptr;
    //const char *src_filename = args->src_filename;
    //uint64_t src_linenum = args->src_linenum;

    target_ulong guest_dword;
    switch (loc_t){
        case LocReg:
            printf("VAR REG: %s %s in Reg %d", var_ty, var_nm, loc);
            printf("    => 0x%x\n", pfun_env->regs[loc]);
            break;
        case LocMem:
            printf("VAR MEM: %s %s @ 0x%x", var_ty, var_nm, loc);
            panda_virtual_memory_rw(pfun_cpu, loc, (uint8_t *)&guest_dword, sizeof(guest_dword), 0);
            printf("    => 0x%x\n", guest_dword);
            break;
        case LocConst:
            printf("VAR CONST: %s %s as 0x%x\n", var_ty, var_nm, loc);
            break;
        case LocErr:
            printf("VAR does not have a location we could determine. Most likely because the var is split among multiple locations\n");
            break;
    }
}
void on_line_change(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    struct args args = {cpu, file_Name, lno};
    printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
    pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *) &args);
}
void on_fn_start(CPUState *cpu, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    struct args args = {cpu, file_Name, lno};
    printf("fn-start: %s() [%s], ln: %4lld, pc @ 0x%x\n",funct_name,file_Name,lno,pc);
    pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *) &args);
}


int virt_mem_helper(CPUState *cpu, target_ulong pc, target_ulong addr, bool isRead) {
    SrcInfo info;
    // if NOT in source code, just return
    int rc = pri_get_pc_source_info(cpu, pc, &info);
    // We are not in dwarf info
    if (rc == -1){
        return 0;
    }
    // We are in the first byte of a .plt function
    if (rc == 1) {
        return 0;
    }
    printf("==%s %ld==\n", info.filename, info.line_number);
    struct args args = {cpu, NULL, 0};
    pri_funct_livevar_iter(cpu, pc, (liveVarCB) pfun, (void *) &args);
    char *symbol_name = pri_get_vma_symbol(cpu, pc, addr);
    if (!symbol_name){
        // symbol was not found for particular addr
        if (isRead) {
            printf ("Virt mem read at 0x%x - (NONE)\n", addr);
        }
        else {
            printf ("Virt mem write at 0x%x - (NONE)\n", addr);
        }
        return 0;
    }
    else {
        if (isRead) {
            printf ("Virt mem read at 0x%x - \"%s\"\n", addr, symbol_name);
        }
        else {
            printf ("Virt mem write at 0x%x - \"%s\"\n", addr, symbol_name);
        }
    }
    return 0;
}

int virt_mem_read(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return virt_mem_helper(cpu, pc, addr, true);

}

int virt_mem_write(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf) {
    return virt_mem_helper(cpu, pc, addr, false);
}
#endif

bool init_plugin(void *self) {

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    //panda_arg_list *args = panda_get_args("pri_taint");
    panda_require("pri");
    assert(init_pri_api());
    panda_require("pri_dwarf");
    assert(init_pri_dwarf_api());

    //PPP_REG_CB("pri", on_before_line_change, on_line_change);
    //PPP_REG_CB("pri", on_fn_start, on_fn_start);
    {
        panda_cb pcb;
        pcb.virt_mem_before_write = virt_mem_write;
        panda_register_callback(self,PANDA_CB_VIRT_MEM_BEFORE_WRITE,pcb);
        pcb.virt_mem_after_read = virt_mem_read;
        panda_register_callback(self,PANDA_CB_VIRT_MEM_AFTER_READ,pcb);
    }
#endif
    return true;
}



void uninit_plugin(void *self) {
}


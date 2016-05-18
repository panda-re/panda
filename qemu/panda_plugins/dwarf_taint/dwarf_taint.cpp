#define __STDC_FORMAT_MACROS

#include "panda/panda_addr.h"
#include "../taint2/label_set.h"
#include "../taint2/taint2.h"
#include <algorithm>

extern "C" {

    
#include "rr_log.h"    
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "pandalog.h"
#include "panda_common.h"

#include "../stpi/stpi_types.h"
#include "../stpi/stpi_ext.h"
#include "../stpi/stpi.h"
#include "../dwarfp/dwarfp_ext.h"
#include "panda_plugin_plugin.h" 
    
// taint 
#include "../taint2/taint2_ext.h"
#include "../taint2/taint2.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel() ;
void set_loglevel(int new_loglevel);
}
CPUState *pfun_env;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
void pfun(const char *var_ty, const char *var_nm, LocType loc_t, target_ulong loc){
    target_ulong guest_dword;
    std::string ty_string = std::string(var_ty);
    size_t num_derefs = std::count(ty_string.begin(), ty_string.end(), '*');
    size_t i;
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
            } 
            break;
        case LocConst:
            //printf("VAR CONST: %s %s as 0x%x\n", var_ty, var_nm, loc);
            break;
        case LocErr:
            printf("VAR does not have a location we could determine. Most likely because the var is split among multiple locations\n");
            break;
        // should not get here
        default:
            assert(1==0);
    }
}
void on_line_change(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    pfun_env = env;
    printf("[%s] %s(), ln: %4lld, pc @ 0x%x\n",file_Name, funct_name,lno,pc);
    stpi_funct_livevar_iter(env, pc, pfun);
}
void on_fn_start(CPUState *env, target_ulong pc, const char *file_Name, const char *funct_name, unsigned long long lno){
    pfun_env = env;
    printf("fn-start: %s() [%s], ln: %4lld, pc @ 0x%x\n",funct_name,file_Name,lno,pc);
    stpi_funct_livevar_iter(env, pc, pfun);
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
    printf("Initializing plugin dwarf_taint\n");
    //panda_arg_list *args = panda_get_args("dwarf_taint");
    panda_require("stpi");
    assert(init_stpi_api());
    panda_require("dwarfp");
    assert(init_dwarfp_api());
    panda_require("taint2");
    assert(init_taint2_api());
    //assert(init_file_taint_api());
    
    PPP_REG_CB("stpi", on_before_line_change, on_line_change);
    //PPP_REG_CB("stpi", on_fn_start, on_fn_start);
    //PPP_REG_CB("taint2", on_taint_change, on_taint_change);
    //taint2_track_taint_state();
#endif
    return true;
}



void uninit_plugin(void *self) {
}


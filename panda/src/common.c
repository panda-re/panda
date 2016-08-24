#include <assert.h>
#include <stdint.h>


#include "qemu/osdep.h"
#include "cpu.h"
#include "disas/disas.h"
#include "../include/panda/plugin.h"
#include "../include/panda/common.h"

target_ulong panda_current_pc(CPUState *cpu) {
    target_ulong pc, cs_base;
    uint32_t flags;
    CPUArchState *env = cpu->env_ptr;  
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    return pc;
}

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
{
  uint32_t table;

  if (address & env->cp15.c2_mask)
    table = env->cp15.c2_base1 & 0xffffc000;
  else
    table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

  return table;
}
#endif

/*
  returns current asid or address-space id.
  architecture-independent
*/
target_ulong panda_current_asid(CPUState *cpu) {
  CPUArchState *env = cpu->env_ptr;
#if (defined TARGET_I386 || defined TARGET_X86_64)
  return env->cr[3];
#elif defined(TARGET_ARM)
  return arm_get_vaddr_table(env, panda_current_pc(env));
#else
#error "panda_current_asid() not implemented for target architecture."
  return 0;
#endif
}

/*
  returns true if we are currently executing in kernel-mode
*/

bool panda_in_kernel(CPUState *cpu) {
   CPUArchState *env = cpu->env_ptr;
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
#error "panda_in_kernel() not implemented for target architecture."
    return false;
#endif
}


void panda_disas(FILE *out, void *code, unsigned long size) {
    disas(out,code,size);
}

const char * valid_os[] = {
    "windows-32-xpsp2", 
    "windows-32-xpsp3", 
    "windows-32-7", 
    "linux-32-lava32",
    "linux-64-3.2.63",
    "linux-32-3.2.65",
    "linux-32-3.2.54",
    NULL
};



PandaOsType panda_os_type = OST_UNKNOWN;
char *panda_os_name = NULL;
uint32_t panda_os_bits = 0;  // 32 or 64
char *panda_os_details = NULL;

void panda_set_os_name(char *os_name) {
    int i=0;
    bool ok_osname = false;
    while (valid_os[i]) {
        if (0 == strcmp(os_name, valid_os[i])) {
            ok_osname = true;
            break;
        }
        i++;
    }
    if (!ok_osname) {
        i=0;
        printf ("os_name=[%s] is not on the list :\n", os_name);
        while (valid_os[i]) {
            printf ("  [%s]\n",  valid_os[i]);
            i++;
        }
        assert (ok_osname);
    }
    panda_os_name = strdup(os_name);
    panda_os_type = OST_UNKNOWN;
    char *p = os_name;
    if (0 == strncmp("windows", os_name, 7))  {
        panda_os_type = OST_WINDOWS;
        p += 8;
    }
    if (0 == strncmp("linux", os_name, 5))  {
        panda_os_type = OST_LINUX;
        p += 6;
    }
    assert (!(panda_os_type == OST_UNKNOWN));
    printf ("p= %s\n", p);
    if (0 == strncmp("32", p, 2)) {
        panda_os_bits = 32;
    }
    if (0 == strncmp("64", p, 2)) {
        panda_os_bits = 64;
    }
    assert (panda_os_bits != 0);
    p += 3;
    panda_os_details = strdup(p);
    printf ("os_type=%d bits=%d os_details=[%s]\n", 
            panda_os_type, panda_os_bits, panda_os_details); 
}


// Note: these call things in exec.c
void panda_invalidate_single_tb(CPUState *cpu, target_ulong pc) {
    breakpoint_invalidate(cpu, pc);
}

int panda_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write) {
    return cpu_physical_memory_rw_ex(addr, buf, len, is_write, true);
}


hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr){
    target_ulong page;
    hwaddr phys_addr;
    page = addr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(env, page);
    /* if no physical page mapped, return an error */
    if (phys_addr == -1)
        return -1;
    phys_addr += (addr & ~TARGET_PAGE_MASK);
    return phys_addr;
}

int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                        uint8_t *buf, int len, int is_write)
{
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        #warning TRL fixme if necessary
        assert (!is_write);
//        if (is_write)
//            cpu_physical_memory_write_rom(phys_addr, buf, l);
//        else {
            ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
            if(ret < 0) return ret;
//        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}


int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                              uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 0);
}


int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                               uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 1);
}


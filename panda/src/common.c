#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "panda/debug.h"
#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/plog.h"
#include "panda/plog-cc-bridge.h"

target_ulong panda_current_pc(CPUState *cpu) {
    target_ulong pc, cs_base;
    uint32_t flags;
    CPUArchState *env = cpu->env_ptr;  
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    return pc;
}

#ifdef TARGET_ARM
/* Return the exception level which controls this address translation regime */
static inline uint32_t regime_el(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_S2NS:
    case ARMMMUIdx_S1E2:
        return 2;
    case ARMMMUIdx_S1E3:
        return 3;
    case ARMMMUIdx_S1SE0:
        return arm_el_is_aa64(env, 3) ? 1 : 3;
    case ARMMMUIdx_S1SE1:
    case ARMMMUIdx_S1NSE0:
    case ARMMMUIdx_S1NSE1:
    case ARMMMUIdx_S12NSE1:
        return 1;
    default:
        g_assert_not_reached();
    }
}

/* Return the TCR controlling this translation regime */
static inline TCR *regime_tcr(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return &env->cp15.vtcr_el2;
    }
    return &env->cp15.tcr_el[regime_el(env, mmu_idx)];
}

/* Return the TTBR associated with this translation regime */
static inline uint64_t regime_ttbr(CPUARMState *env, ARMMMUIdx mmu_idx,
                                   int ttbrn)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return env->cp15.vttbr_el2;
    }
    if (ttbrn == 0) {
        return env->cp15.ttbr0_el[regime_el(env, mmu_idx)];
    } else {
        return env->cp15.ttbr1_el[regime_el(env, mmu_idx)];
    }
}

// ARM: stolen get_level1_table_address ()
// from target-arm/helper.c
bool arm_get_vaddr_table(CPUState *cpu, uint32_t *table, uint32_t address);
bool arm_get_vaddr_table(CPUState *cpu, uint32_t *table, uint32_t address)
{
    CPUARMState *env = (CPUARMState *)cpu->env_ptr;
    ARMMMUIdx mmu_idx = cpu_mmu_index(env, false);
    /* Note that we can only get here for an AArch32 PL0/PL1 lookup */
    TCR *tcr = regime_tcr(env, mmu_idx);

    if (address & tcr->mask) {
        if (tcr->raw_tcr & TTBCR_PD1) {
            /* Translation table walk disabled for TTBR1 */
            return false;
        }
        *table = regime_ttbr(env, mmu_idx, 1) & 0xffffc000;
    } else {
        if (tcr->raw_tcr & TTBCR_PD0) {
            /* Translation table walk disabled for TTBR0 */
            return false;
        }
        *table = regime_ttbr(env, mmu_idx, 0) & tcr->base_mask;
    }
    *table |= (address >> 18) & 0x3ffc;
    return true;
}
#endif

/*
  returns current asid or address-space id.
  architecture-independent
*/
target_ulong panda_current_asid(CPUState *cpu) {
#if defined(TARGET_I386)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  return env->cr[3];
#elif defined(TARGET_ARM)
  target_ulong table;
  bool rc = arm_get_vaddr_table(cpu,
          &table,
          panda_current_pc(cpu));
  assert(rc);
  return table;
  /*return arm_get_vaddr_table(env, panda_current_pc(env));*/
#elif defined(TARGET_PPC)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  return env->sr[0];
#else
#error "panda_current_asid() not implemented for target architecture."
  return 0;
#endif
}

/*
  returns current stack pointer.
  architecture-independent
*/
target_ulong panda_current_sp(CPUState *cpu) {
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
  return env->regs[R_ESP];
#elif defined(TARGET_ARM)
  // R13 on ARM.
  return env->regs[13];
#elif defined(TARGET_PPC)
  // R1 on PPC.
  return env->gpr[1];
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
#elif defined(TARGET_PPC)
    return msr_pr;
#else
#error "panda_in_kernel() not implemented for target architecture."
    return false;
#endif
}


void panda_disas(FILE *out, void *code, unsigned long size) {
    disas(out,code,size);
}


// regular expressions used to validate the -os option
const char * valid_os_re[] = {
    "windows[-_]32[-_]xpsp[23]",
    "windows[-_]32[-_]7",
    "linux[-_]32[-_].+",
    "linux[-_]64[-_].+",
    NULL
};


gchar *panda_os_name = NULL;                // the full name of the os, as provided by the user
gchar *panda_os_family = NULL;              // parsed os family
gchar *panda_os_variant = NULL;             // parsed os variant
uint32_t panda_os_bits = 0;                 // parsed os bits
PandaOsFamily panda_os_familyno = OS_UNKNOWN; // numeric identifier for family

void panda_set_os_name(char *os_name) {
    // validate os_name before parsing its components
    gboolean os_supported = FALSE;
    const gchar **os_re;
    for (os_re=valid_os_re; *os_re != NULL; os_re++) {
        if (g_regex_match_simple(*os_re, os_name, 0, 0)) {
            os_supported = TRUE;
            break;
        }
        //fprintf(stderr, "%s does not match regex %s\n", os_name, *os_re);
    }
    assert(os_supported);

    // set os name and split it
    panda_os_name = g_strdup(os_name);
    gchar **osparts = g_strsplit(panda_os_name, "-", 3);

    // set os type
    if (0 == g_ascii_strncasecmp("windows", osparts[0], strlen("windows"))) { panda_os_familyno = OS_WINDOWS; }
    else if (0 == g_ascii_strncasecmp("linux", osparts[0], strlen("linux"))) { panda_os_familyno = OS_LINUX; }
    else { panda_os_familyno = OS_UNKNOWN; }

    // set os bits
    if (0 == g_ascii_strncasecmp("32", osparts[1], strlen("32"))) { panda_os_bits = 32; }
    else if (0 == g_ascii_strncasecmp("64", osparts[1], strlen("64"))) { panda_os_bits = 64; }
    else { panda_os_bits = 0; }

    // set os family and variant
    // These values are not used here, but are available to other plugins.
    // E.g. osi_linux uses panda_os_variant to load the appropriate kernel
    // profile from kernelinfo.conf at runtime.
    panda_os_family = g_strdup(osparts[0]);
    panda_os_variant = g_strdup(osparts[2]);

    // abort for invalid os type/bits
    assert (!(panda_os_familyno == OS_UNKNOWN));
    assert (panda_os_bits != 0);
    g_strfreev(osparts);

    fprintf(stderr, PANDA_MSG_FMT "os_familyno=%d bits=%d os_details=%s\n", PANDA_CORE_NAME, panda_os_familyno, panda_os_bits, panda_os_variant);
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
        ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
        if(ret < 0) return ret;
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


void panda_cleanup(void) {
    // PANDA: unload plugins
    panda_unload_plugins();
    if (pandalog) {
        pandalog_cc_close();
    }
}

/* vim:set shiftwidth=4 ts=4 sts=4 et: */

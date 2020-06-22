#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "panda/debug.h"
#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/plog.h"
#include "panda/plog-cc-bridge.h"

#if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
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
        printf("Unimplemented code for MMU_IDX: %d\n", mmu_idx);
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

    /* For EL0 and EL1, TBI is controlled by stage 1's TCR, so convert
       * a stage 1+2 mmu index into the appropriate stage 1 mmu index.
       */
    if (mmu_idx == ARMMMUIdx_S12NSE0 || mmu_idx == ARMMMUIdx_S12NSE1) {
        mmu_idx += ARMMMUIdx_S1NSE0;
    }

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
#elif defined(TARGET_ARM) && !defined(TARGET_AARCH64)
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
#elif defined(TARGET_MIPS)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  return (env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask);
#else
#error "panda_current_asid() not implemented for target architecture."
  return 0;
#endif
}

target_ulong panda_current_pc(CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    target_ulong pc, cs_base;
    uint32_t flags;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    return pc;
}

/**
 * @brief Wrapper around QEMU's disassembly function.
 */
void panda_disas(FILE *out, void *code, unsigned long size) {
    disas(out, code, size);
}

// regular expressions used to validate the -os option
const char * valid_os_re[] = {
    "windows[-_]32[-_]xpsp[23]",
    "windows[-_]32[-_]7",
    "windows[-_]32[-_]2000",
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
    bool os_supported = false;
    const gchar **os_re;
    for (os_re=valid_os_re; *os_re != NULL; os_re++) {
        if (g_regex_match_simple(*os_re, os_name, 0, 0)) {
            os_supported = true;
            break;
        }
        //fprintf(stderr, "%s does not match regex %s\n", os_name, *os_re);
    }
    assert(os_supported);

    // set os name and split it
    panda_os_name = g_strdup(os_name);
    gchar **osparts = g_strsplit_set(panda_os_name, "-_", 3);

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

void panda_cleanup(void) {
    // PANDA: unload plugins
    panda_unload_plugins();
    if (pandalog) {
        pandalog_cc_close();
    }
}

/* Board-agnostic search for RAM memory region */
MemoryRegion* panda_find_ram(void) {

    Int128 curr_max = 0;
    MemoryRegion *ram = NULL;   // Sentinel, deref segfault
    MemoryRegion *sys_mem = get_system_memory();
    MemoryRegion *mr_check;
    MemoryRegion *mr_iter;

    // Largest top-level subregion marked as random access memory, accounting for possible aliases
    QTAILQ_FOREACH(mr_iter, &(sys_mem->subregions), subregions_link) {

        mr_check = mr_iter;

        if (mr_iter->alias && (mr_iter->alias->size > mr_iter->size)) {
           mr_check = mr_iter->alias;
        }

        if (memory_region_is_ram(mr_check) && (mr_check->size > curr_max)) {
            curr_max = mr_check->size;
            ram = mr_check;
        }
    }

    return ram;
}

#ifdef TARGET_ARM
#define CPSR_M (0x1fU)
#define ARM_CPU_MODE_SVC 0x13
static int saved_cpsr = -1;
static int saved_r13 = -1;
static bool in_fake_priv = false;

// Force the guest into supervisor mode by directly modifying its cpsr and r13
// See https://developer.arm.com/docs/ddi0595/b/aarch32-system-registers/cpsr
bool enter_priv(CPUState* cpu) {
    CPUARMState* env = ((CPUARMState*)cpu->env_ptr);

    saved_cpsr = env->uncached_cpsr;
    env->uncached_cpsr = (env->uncached_cpsr) | (ARM_CPU_MODE_SVC & CPSR_M);
    if (env->uncached_cpsr == saved_cpsr) {
        // No change was made
        return false;
    }

    assert(!in_fake_priv && "enter_priv called when already entered");

    // Should we also restore other banked regs like r_14? Seems unnecessary?
    saved_r13 = env->regs[13];
    // If we're not already in SVC mode, load the saved SVC r13 from the SVC mode's banked_r13
    if ((((CPUARMState*)cpu->env_ptr)->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_SVC) {
        env->regs[13] = env->banked_r13[ /*SVC_MODE=>*/ 1 ];
    }
    in_fake_priv = true;
    return true;
}

// return to whatever mode we were in previously (might be a NO-OP if we were in svc)
// Assumes you've called enter_svc first
void exit_priv(CPUState* cpu) {
    //printf("RESTORING CSPR TO 0x%x\n", saved_cpsr);
    assert(in_fake_priv && "exit called when not faked");

    assert(saved_cpsr != -1 && "Must call enter_svc before reverting with exit_svc");
    CPUARMState* env = ((CPUARMState*)cpu->env_ptr);

    env->uncached_cpsr = saved_cpsr;
    env->regs[13] = saved_r13;
    in_fake_priv = false;
}


#else
// Non-ARM architectures don't require special permissions for PANDA's memory access fns
bool enter_priv(CPUState* cpu) {return false;};
void exit_priv(CPUState* cpu)  {};
#endif

/* vim:set shiftwidth=4 ts=4 sts=4 et: */

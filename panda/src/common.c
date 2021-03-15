#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "panda/debug.h"
#include "panda/plugin.h"
#include "panda/common.h"
#include "panda/plugin_api.h"
#include "panda/plog.h"
#include "panda/plog-cc-bridge.h"

#if defined(TARGET_ARM)
/* Return the exception level which controls this address translation regime */
uint32_t regime_el(CPUARMState *env, ARMMMUIdx mmu_idx)
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
TCR *regime_tcr(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return &env->cp15.vtcr_el2;
    }
    return &env->cp15.tcr_el[regime_el(env, mmu_idx)];
}

/* Return the TTBR associated with this translation regime */
uint64_t regime_ttbr(CPUARMState *env, ARMMMUIdx mmu_idx,
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
#if defined(TARGET_AARCH64)
  return 0; // XXX: TODO
#else
  target_ulong table;
  bool rc = arm_get_vaddr_table(cpu,
          &table,
          panda_current_pc(cpu));
  assert(rc);
  return table;
  /*return arm_get_vaddr_table(env, panda_current_pc(env));*/
#endif
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
    "freebsd[-_]32[-_].+",
    "freebsd[-_]64[-_].+",
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
    else if (0 == g_ascii_strncasecmp("freebsd", osparts[0], strlen("freebsd"))) { panda_os_familyno = OS_FREEBSD; }
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
static int saved_pstate = -1;

// Force the guest into supervisor mode by directly modifying its cpsr and r13
// See https://developer.arm.com/docs/ddi0595/b/aarch32-system-registers/cpsr
bool enter_priv(CPUState* cpu) {
    CPUARMState* env = ((CPUARMState*)cpu->env_ptr);

    if (env->aarch64) {
        saved_pstate = env->pstate;
        env->pstate |= 1<<2; // Set bits 2-4 to 1 - EL1
        if (saved_pstate == env->pstate) {
            return false;
        }
    }else{
        saved_cpsr = env->uncached_cpsr;
        env->uncached_cpsr = (env->uncached_cpsr) | (ARM_CPU_MODE_SVC & CPSR_M);
        if (env->uncached_cpsr == saved_cpsr) {
            // No change was made
            return false;
        }
    }

    assert(!in_fake_priv && "enter_priv called when already entered");

    if (!env->aarch64) {
        // arm32: save r13 for osi - Should we also restore other banked regs like r_14? Seems unnecessary?
        saved_r13 = env->regs[13];
        // If we're not already in SVC mode, load the saved SVC r13 from the SVC mode's banked_r13
        if ((((CPUARMState*)cpu->env_ptr)->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_SVC) {
            env->regs[13] = env->banked_r13[ /*SVC_MODE=>*/ 1 ];
        }
    }
    in_fake_priv = true;
    return true;
}

// return to whatever mode we were in previously (might be a NO-OP if we were in svc)
// Assumes you've called enter_svc first
void exit_priv(CPUState* cpu) {
    //printf("RESTORING CSPR TO 0x%x\n", saved_cpsr);
    assert(in_fake_priv && "exit called when not faked");

    CPUARMState* env = ((CPUARMState*)cpu->env_ptr);

    if (env->aarch64) {
        assert(saved_pstate != -1 && "Must call enter_svc before reverting with exit_svc");
        env->pstate = saved_pstate;
    }else{
        assert(saved_cpsr != -1 && "Must call enter_svc before reverting with exit_svc");
        env->uncached_cpsr = saved_cpsr;
        env->regs[13] = saved_r13;
    }
    in_fake_priv = false;
}


#elif defined(TARGET_MIPS)
// MIPS
static int saved_hflags = -1;
static bool in_fake_priv = false;

// Force the guest into supervisor mode by modifying env->hflags
// save old hflags and restore after the read
bool enter_priv(CPUState* cpu) {
    saved_hflags = ((CPUMIPSState*)cpu->env_ptr)->hflags;
    CPUMIPSState *env =  (CPUMIPSState*)cpu->env_ptr;

    // Already in kernel mode?
    if (!(env->hflags & MIPS_HFLAG_UM) && !(env->hflags & MIPS_HFLAG_SM)) {
        // No point in changing permissions
        return false;
    }

    // Disable usermode & supervisor mode - puts us in kernel mode
    ((CPUMIPSState*)cpu->env_ptr)->hflags = ((CPUMIPSState*)cpu->env_ptr)->hflags & ~MIPS_HFLAG_UM;
    ((CPUMIPSState*)cpu->env_ptr)->hflags = ((CPUMIPSState*)cpu->env_ptr)->hflags & ~MIPS_HFLAG_SM;

    in_fake_priv = true;

    return true;
}

void exit_priv(CPUState* cpu) {
    assert(in_fake_priv && "exit called when not faked");
    ((CPUMIPSState*)cpu->env_ptr)->hflags = saved_hflags;
    in_fake_priv = false;
}


#else
// Non-ARM architectures don't require special permissions for PANDA's memory access fns
bool enter_priv(CPUState* cpu) {return false;};
void exit_priv(CPUState* cpu)  {};
#endif

target_ptr_t tb_get_pc(TranslationBlock * tb) {
  return tb->pc;
}

size_t tb_get_size(TranslationBlock * tb) {
  return tb->size;
}

unsigned int tb_get_icount(TranslationBlock * tb) {
  return tb->icount;
}

bool panda_in_kernel(const CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    // See target/arm/cpu.h arm_current_el
    if (env->aarch64) {
        return extract32(env->pstate, 2, 2) > 0;
    }
    // Note: returns true for non-SVC modes (hypervisor, monitor, system, etc).
    // See: https://www.keil.com/pack/doc/cmsis/Core_A/html/group__CMSIS__CPSR__M.html
    return ((env->uncached_cpsr & CPSR_M) > ARM_CPU_MODE_USR);
#elif defined(TARGET_PPC)
    return msr_pr;
#elif defined(TARGET_MIPS)
    return (env->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_KM;
#else
#error "panda_in_kernel() not implemented for target architecture."
    return false;
#endif
}

target_ulong panda_current_ksp(CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    if (panda_in_kernel(cpu)) {
        // Return directly the ESP register value.
        return env->regs[R_ESP];
    } else {
        // Returned kernel ESP stored in the TSS.
        // Related reading: https://css.csail.mit.edu/6.858/2018/readings/i386/c07.htm
        const uint32_t esp0 = 4;
        const target_ulong tss_base = ((CPUX86State *)env)->tr.base + esp0;
        target_ulong kernel_esp = 0;
        if (panda_virtual_memory_rw(cpu, tss_base, (uint8_t *)&kernel_esp, sizeof(kernel_esp), false ) < 0) {
            return 0;
        }
        return kernel_esp;
    }
#elif defined(TARGET_ARM)
    if(env->aarch64) {
        return env->sp_el[1];
    } else {
        if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC) {
            return env->regs[13];
        }else {
            // Read banked R13 for SVC mode to get the kernel SP (1=>SVC bank from target/arm/internals.h)
            return env->banked_r13[1];
        }
    }
#elif defined(TARGET_PPC)
    // R1 on PPC.
    return env->gpr[1];
#elif defined(TARGET_MIPS)
    return env->active_tc.gpr[MIPS_SP];
#else
#error "panda_current_ksp() not implemented for target architecture."
    return 0;
#endif
}

target_ulong panda_current_sp(const CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    // valid on x86 and x86_64
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    // R13 on ARM.
    return env->regs[13];
#elif defined(TARGET_PPC)
    // R1 on PPC.
    return env->gpr[1];
#elif defined(TARGET_MIPS)
    return env->active_tc.gpr[MIPS_SP];
#else
#error "panda_current_sp() not implemented for target architecture."
    return 0;
#endif
}

target_ulong panda_get_retval(const CPUState *cpu) {
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
#if defined(TARGET_I386)
    // EAX for x86.
    return env->regs[R_EAX];
#elif defined(TARGET_ARM)
    // R0 on ARM.
    return env->regs[0];
#elif defined(TARGET_PPC)
    // R3 on PPC.
    return env->gpr[3];
#elif defined(TARGET_MIPS)
    // MIPS has 2 return registers v0 and v1. Here we choose v0.
    return env->active_tc.gpr[MIPS_V0];
#else
#error "panda_get_retval() not implemented for target architecture."
    return 0;
#endif
}

int panda_physical_memory_rw(hwaddr addr, uint8_t *buf, int len,
                                           bool is_write) {
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr = address_space_translate(&address_space_memory, addr,
                                               &addr1, &l, is_write);

    if (!memory_access_is_direct(mr, is_write)) {
        // fail for MMIO regions of physical address space
        return MEMTX_ERROR;
    }
    void *ram_ptr = qemu_map_ram_ptr(mr->ram_block, addr1);

    if (is_write) {
        memcpy(ram_ptr, buf, len);
    } else {
        memcpy(buf, ram_ptr, len);
    }
    return MEMTX_OK;
}

hwaddr panda_virt_to_phys(CPUState *env, target_ulong addr) {
    target_ulong page;
    hwaddr phys_addr;
    page = addr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(env, page);
    if (phys_addr == -1) {
        // no physical page mapped
        return -1;
    }
    phys_addr += (addr & ~TARGET_PAGE_MASK);
    return phys_addr;
}

int panda_virtual_memory_rw(CPUState *env, target_ulong addr,
                                          uint8_t *buf, int len, bool is_write) {
    int l;
    int ret;
    hwaddr phys_addr;
    target_ulong page;
    bool changed_priv = false;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_debug(env, page);
        // If we failed and we aren't in priv mode and we CAN go into it, toggle modes and try again
        if (phys_addr == -1  && !changed_priv && (changed_priv=enter_priv(env))) {
            phys_addr = cpu_get_phys_page_debug(env, page);
            //if (phys_addr != -1) printf("[panda dbg] virt->phys failed until privileged mode\n");
        }

        // No physical page mapped, even after potential privileged switch, abort
        if (phys_addr == -1)  {
            if (changed_priv) exit_priv(env); // Cleanup mode if necessary
            return -1;
        }

        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len) {
            l = len;
        }
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);

        // Failed and privileged mode wasn't already enabled - enable priv and retry if we can
        if (ret != MEMTX_OK && !changed_priv && (changed_priv = enter_priv(env))) {
            ret = panda_physical_memory_rw(phys_addr, buf, l, is_write);
            //if (ret == MEMTX_OK) printf("[panda dbg] accessing phys failed until privileged mode\n");
        }
        // Still failed, even after potential privileged switch, abort
        if (ret != MEMTX_OK) {
            if (changed_priv) exit_priv(env); // Cleanup mode if necessary
            return ret;
        }

        len -= l;
        buf += l;
        addr += l;
    }
    if (changed_priv) exit_priv(env); // Clear privileged mode if necessary
    return 0;
}

/**
 * @brief Reads/writes data into/from \p buf from/to guest virtual address \p addr.
 *
 * For ARM/MIPS we switch into privileged mode if the access fails. The mode is always reset
 * before we return.
 */

/**
 * @brief Reads data into \p buf from guest virtual address \p addr.
 */
int panda_virtual_memory_read(CPUState *env, target_ulong addr,
                                            uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 0);
}

/**
 * @brief Writes data from \p buf data to guest virtual address \p addr.
 */
int panda_virtual_memory_write(CPUState *env, target_ulong addr,
                                             uint8_t *buf, int len) {
    return panda_virtual_memory_rw(env, addr, buf, len, 1);
}

/**
 * @brief Obtains a host pointer for the given virtual address.
 */
void *panda_map_virt_to_host(CPUState *env, target_ulong addr,
                                           int len)
{
    hwaddr phys = panda_virt_to_phys(env, addr);
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion *mr =
        address_space_translate(&address_space_memory, phys, &addr1, &l, true);

    if (!memory_access_is_direct(mr, true)) {
        return NULL;
    }

    return qemu_map_ram_ptr(mr->ram_block, addr1);
}

/**
 * @brief Translate a physical address to a RAM Offset (needed for the taint system)
 * Returns MEMTX_OK on success.
 */
MemTxResult PandaPhysicalAddressToRamOffset(ram_addr_t* out, hwaddr addr, bool is_write)
{
    hwaddr TranslatedAddress;
    hwaddr AccessLength = 1;
    MemoryRegion* mr;
    ram_addr_t RamOffset;

    rcu_read_lock();
    mr = address_space_translate(&address_space_memory, addr, &TranslatedAddress, &AccessLength, is_write);

    if (!mr || !memory_region_is_ram(mr) || memory_region_is_ram_device(mr) || memory_region_is_romd(mr) || (is_write && mr->readonly))
    {
        /*
            We only want actual RAM.
            I can't find a concrete instance of a RAM Device,
            but from the docs/comments I can find, this seems
            like the appropriate check.
        */
        rcu_read_unlock();
        return MEMTX_ERROR;
    }

    if ((RamOffset = memory_region_get_ram_addr(mr)) == RAM_ADDR_INVALID)
    {
        rcu_read_unlock();
        return MEMTX_ERROR;
    }

    rcu_read_unlock();

    RamOffset += TranslatedAddress;

    if (RamOffset >= ram_size)
    {
        /*
            HACK
            For the moment, the taint system (the only consumer of this) will die in very unfortunate
            ways if the translated offset exceeds the size of "RAM" (the argument given to -m in
            qemu's invocation)...
            Unfortunately there's other "RAM" qemu tracks that's not differentiable in a target-independent
            way. For instance: the PC BIOS memory and VGA memory. In the future it would probably be easier
            to modify the taint system to use last_ram_offset() rather tham ram_size, and/or register an
            address space listener to update it's shadow RAM with qemu's hotpluggable memory.
            From brief observation, the qemu machine implementations seem to map the system "RAM"
            people are most likely thinking about when they say "RAM" first, so the ram_addr_t values
            below ram_size should belong to those memory regions. This isn't required however, so beware.
        */
        fprintf(stderr, "PandaPhysicalAddressToRamOffset: Translated Physical Address 0x" TARGET_FMT_plx " has RAM Offset Above ram_size (0x" RAM_ADDR_FMT " >= 0x" RAM_ADDR_FMT ")\n", addr, RamOffset, ram_size);
        return MEMTX_DECODE_ERROR;
    }

    if (out)
        *out = RamOffset;

    return MEMTX_OK;
}

/**
 * @brief Translate a virtual address to a RAM Offset (needed for the taint system)
 * Returns MEMTX_OK on success.
 */
MemTxResult PandaVirtualAddressToRamOffset(ram_addr_t* out, CPUState* cpu, target_ulong addr, bool is_write)
{
    hwaddr PhysicalAddress = panda_virt_to_phys(cpu, addr);
    if (PhysicalAddress == (hwaddr)-1)
        return MEMTX_ERROR;
    return PandaPhysicalAddressToRamOffset(out, PhysicalAddress, is_write);
}

bool pandalog_set(void) {
    return pandalog;
}

/* vim:set shiftwidth=4 ts=4 sts=4 et: */

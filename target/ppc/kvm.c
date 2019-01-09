/*
 * PowerPC implementation of KVM hooks
 *
 * Copyright IBM Corp. 2007
 * Copyright (C) 2011 Freescale Semiconductor, Inc.
 *
 * Authors:
 *  Jerone Young <jyoung5@us.ibm.com>
 *  Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *  Hollis Blanchard <hollisb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

#include <linux/kvm.h>

#include "qemu-common.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "cpu-models.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "sysemu/hw_accel.h"
#include "kvm_ppc.h"
#include "sysemu/cpus.h"
#include "sysemu/device_tree.h"
#include "mmu-hash64.h"

#include "hw/sysbus.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"
#include "hw/ppc/spapr_cpu_core.h"
#include "hw/ppc/ppc.h"
#include "sysemu/watchdog.h"
#include "trace.h"
#include "exec/gdbstub.h"
#include "exec/memattrs.h"
#include "exec/ram_addr.h"
#include "sysemu/hostmem.h"
#include "qemu/cutils.h"
#include "qemu/mmap-alloc.h"
#if defined(TARGET_PPC64)
#include "hw/ppc/spapr_cpu_core.h"
#endif

//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define PROC_DEVTREE_CPU      "/proc/device-tree/cpus/"

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_LAST_INFO
};

static int cap_interrupt_unset = false;
static int cap_interrupt_level = false;
static int cap_segstate;
static int cap_booke_sregs;
static int cap_ppc_smt;
static int cap_ppc_rma;
static int cap_spapr_tce;
static int cap_spapr_multitce;
static int cap_spapr_vfio;
static int cap_hior;
static int cap_one_reg;
static int cap_epr;
static int cap_ppc_watchdog;
static int cap_papr;
static int cap_htab_fd;
static int cap_fixup_hcalls;
static int cap_htm;             /* Hardware transactional memory support */

static uint32_t debug_inst_opcode;

/* XXX We have a race condition where we actually have a level triggered
 *     interrupt, but the infrastructure can't expose that yet, so the guest
 *     takes but ignores it, goes to sleep and never gets notified that there's
 *     still an interrupt pending.
 *
 *     As a quick workaround, let's just wake up again 20 ms after we injected
 *     an interrupt. That way we can assure that we're always reinjecting
 *     interrupts in case the guest swallowed them.
 */
static QEMUTimer *idle_timer;

static void kvm_kick_cpu(void *opaque)
{
    PowerPCCPU *cpu = opaque;

    qemu_cpu_kick(CPU(cpu));
}

/* Check whether we are running with KVM-PR (instead of KVM-HV).  This
 * should only be used for fallback tests - generally we should use
 * explicit capabilities for the features we want, rather than
 * assuming what is/isn't available depending on the KVM variant. */
static bool kvmppc_is_pr(KVMState *ks)
{
    /* Assume KVM-PR if the GET_PVINFO capability is available */
    return kvm_check_extension(ks, KVM_CAP_PPC_GET_PVINFO) != 0;
}

static int kvm_ppc_register_host_cpu_type(void);

int kvm_arch_init(MachineState *ms, KVMState *s)
{
    cap_interrupt_unset = kvm_check_extension(s, KVM_CAP_PPC_UNSET_IRQ);
    cap_interrupt_level = kvm_check_extension(s, KVM_CAP_PPC_IRQ_LEVEL);
    cap_segstate = kvm_check_extension(s, KVM_CAP_PPC_SEGSTATE);
    cap_booke_sregs = kvm_check_extension(s, KVM_CAP_PPC_BOOKE_SREGS);
    cap_ppc_smt = kvm_check_extension(s, KVM_CAP_PPC_SMT);
    cap_ppc_rma = kvm_check_extension(s, KVM_CAP_PPC_RMA);
    cap_spapr_tce = kvm_check_extension(s, KVM_CAP_SPAPR_TCE);
    cap_spapr_multitce = kvm_check_extension(s, KVM_CAP_SPAPR_MULTITCE);
    cap_spapr_vfio = false;
    cap_one_reg = kvm_check_extension(s, KVM_CAP_ONE_REG);
    cap_hior = kvm_check_extension(s, KVM_CAP_PPC_HIOR);
    cap_epr = kvm_check_extension(s, KVM_CAP_PPC_EPR);
    cap_ppc_watchdog = kvm_check_extension(s, KVM_CAP_PPC_BOOKE_WATCHDOG);
    /* Note: we don't set cap_papr here, because this capability is
     * only activated after this by kvmppc_set_papr() */
    cap_htab_fd = kvm_check_extension(s, KVM_CAP_PPC_HTAB_FD);
    cap_fixup_hcalls = kvm_check_extension(s, KVM_CAP_PPC_FIXUP_HCALL);
    cap_htm = kvm_vm_check_extension(s, KVM_CAP_PPC_HTM);

    if (!cap_interrupt_level) {
        fprintf(stderr, "KVM: Couldn't find level irq capability. Expect the "
                        "VM to stall at times!\n");
    }

    kvm_ppc_register_host_cpu_type();

    return 0;
}

int kvm_arch_irqchip_create(MachineState *ms, KVMState *s)
{
    return 0;
}

static int kvm_arch_sync_sregs(PowerPCCPU *cpu)
{
    CPUPPCState *cenv = &cpu->env;
    CPUState *cs = CPU(cpu);
    struct kvm_sregs sregs;
    int ret;

    if (cenv->excp_model == POWERPC_EXCP_BOOKE) {
        /* What we're really trying to say is "if we're on BookE, we use
           the native PVR for now". This is the only sane way to check
           it though, so we potentially confuse users that they can run
           BookE guests on BookS. Let's hope nobody dares enough :) */
        return 0;
    } else {
        if (!cap_segstate) {
            fprintf(stderr, "kvm error: missing PVR setting capability\n");
            return -ENOSYS;
        }
    }

    ret = kvm_vcpu_ioctl(cs, KVM_GET_SREGS, &sregs);
    if (ret) {
        return ret;
    }

    sregs.pvr = cenv->spr[SPR_PVR];
    return kvm_vcpu_ioctl(cs, KVM_SET_SREGS, &sregs);
}

/* Set up a shared TLB array with KVM */
static int kvm_booke206_tlb_init(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    struct kvm_book3e_206_tlb_params params = {};
    struct kvm_config_tlb cfg = {};
    unsigned int entries = 0;
    int ret, i;

    if (!kvm_enabled() ||
        !kvm_check_extension(cs->kvm_state, KVM_CAP_SW_TLB)) {
        return 0;
    }

    assert(ARRAY_SIZE(params.tlb_sizes) == BOOKE206_MAX_TLBN);

    for (i = 0; i < BOOKE206_MAX_TLBN; i++) {
        params.tlb_sizes[i] = booke206_tlb_size(env, i);
        params.tlb_ways[i] = booke206_tlb_ways(env, i);
        entries += params.tlb_sizes[i];
    }

    assert(entries == env->nb_tlb);
    assert(sizeof(struct kvm_book3e_206_tlb_entry) == sizeof(ppcmas_tlb_t));

    env->tlb_dirty = true;

    cfg.array = (uintptr_t)env->tlb.tlbm;
    cfg.array_len = sizeof(ppcmas_tlb_t) * entries;
    cfg.params = (uintptr_t)&params;
    cfg.mmu_type = KVM_MMU_FSL_BOOKE_NOHV;

    ret = kvm_vcpu_enable_cap(cs, KVM_CAP_SW_TLB, 0, (uintptr_t)&cfg);
    if (ret < 0) {
        fprintf(stderr, "%s: couldn't enable KVM_CAP_SW_TLB: %s\n",
                __func__, strerror(-ret));
        return ret;
    }

    env->kvm_sw_tlb = true;
    return 0;
}


#if defined(TARGET_PPC64)
static void kvm_get_fallback_smmu_info(PowerPCCPU *cpu,
                                       struct kvm_ppc_smmu_info *info)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    memset(info, 0, sizeof(*info));

    /* We don't have the new KVM_PPC_GET_SMMU_INFO ioctl, so
     * need to "guess" what the supported page sizes are.
     *
     * For that to work we make a few assumptions:
     *
     * - Check whether we are running "PR" KVM which only supports 4K
     *   and 16M pages, but supports them regardless of the backing
     *   store characteritics. We also don't support 1T segments.
     *
     *   This is safe as if HV KVM ever supports that capability or PR
     *   KVM grows supports for more page/segment sizes, those versions
     *   will have implemented KVM_CAP_PPC_GET_SMMU_INFO and thus we
     *   will not hit this fallback
     *
     * - Else we are running HV KVM. This means we only support page
     *   sizes that fit in the backing store. Additionally we only
     *   advertize 64K pages if the processor is ARCH 2.06 and we assume
     *   P7 encodings for the SLB and hash table. Here too, we assume
     *   support for any newer processor will mean a kernel that
     *   implements KVM_CAP_PPC_GET_SMMU_INFO and thus doesn't hit
     *   this fallback.
     */
    if (kvmppc_is_pr(cs->kvm_state)) {
        /* No flags */
        info->flags = 0;
        info->slb_size = 64;

        /* Standard 4k base page size segment */
        info->sps[0].page_shift = 12;
        info->sps[0].slb_enc = 0;
        info->sps[0].enc[0].page_shift = 12;
        info->sps[0].enc[0].pte_enc = 0;

        /* Standard 16M large page size segment */
        info->sps[1].page_shift = 24;
        info->sps[1].slb_enc = SLB_VSID_L;
        info->sps[1].enc[0].page_shift = 24;
        info->sps[1].enc[0].pte_enc = 0;
    } else {
        int i = 0;

        /* HV KVM has backing store size restrictions */
        info->flags = KVM_PPC_PAGE_SIZES_REAL;

        if (env->mmu_model & POWERPC_MMU_1TSEG) {
            info->flags |= KVM_PPC_1T_SEGMENTS;
        }

        if (POWERPC_MMU_VER(env->mmu_model) == POWERPC_MMU_VER_2_06 ||
           POWERPC_MMU_VER(env->mmu_model) == POWERPC_MMU_VER_2_07) {
            info->slb_size = 32;
        } else {
            info->slb_size = 64;
        }

        /* Standard 4k base page size segment */
        info->sps[i].page_shift = 12;
        info->sps[i].slb_enc = 0;
        info->sps[i].enc[0].page_shift = 12;
        info->sps[i].enc[0].pte_enc = 0;
        i++;

        /* 64K on MMU 2.06 and later */
        if (POWERPC_MMU_VER(env->mmu_model) == POWERPC_MMU_VER_2_06 ||
            POWERPC_MMU_VER(env->mmu_model) == POWERPC_MMU_VER_2_07) {
            info->sps[i].page_shift = 16;
            info->sps[i].slb_enc = 0x110;
            info->sps[i].enc[0].page_shift = 16;
            info->sps[i].enc[0].pte_enc = 1;
            i++;
        }

        /* Standard 16M large page size segment */
        info->sps[i].page_shift = 24;
        info->sps[i].slb_enc = SLB_VSID_L;
        info->sps[i].enc[0].page_shift = 24;
        info->sps[i].enc[0].pte_enc = 0;
    }
}

static void kvm_get_smmu_info(PowerPCCPU *cpu, struct kvm_ppc_smmu_info *info)
{
    CPUState *cs = CPU(cpu);
    int ret;

    if (kvm_check_extension(cs->kvm_state, KVM_CAP_PPC_GET_SMMU_INFO)) {
        ret = kvm_vm_ioctl(cs->kvm_state, KVM_PPC_GET_SMMU_INFO, info);
        if (ret == 0) {
            return;
        }
    }

    kvm_get_fallback_smmu_info(cpu, info);
}

static bool kvm_valid_page_size(uint32_t flags, long rampgsize, uint32_t shift)
{
    if (!(flags & KVM_PPC_PAGE_SIZES_REAL)) {
        return true;
    }

    return (1ul << shift) <= rampgsize;
}

static long max_cpu_page_size;

static void kvm_fixup_page_sizes(PowerPCCPU *cpu)
{
    static struct kvm_ppc_smmu_info smmu_info;
    static bool has_smmu_info;
    CPUPPCState *env = &cpu->env;
    int iq, ik, jq, jk;
    bool has_64k_pages = false;

    /* We only handle page sizes for 64-bit server guests for now */
    if (!(env->mmu_model & POWERPC_MMU_64)) {
        return;
    }

    /* Collect MMU info from kernel if not already */
    if (!has_smmu_info) {
        kvm_get_smmu_info(cpu, &smmu_info);
        has_smmu_info = true;
    }

    if (!max_cpu_page_size) {
        max_cpu_page_size = qemu_getrampagesize();
    }

    /* Convert to QEMU form */
    memset(&env->sps, 0, sizeof(env->sps));

    /* If we have HV KVM, we need to forbid CI large pages if our
     * host page size is smaller than 64K.
     */
    if (smmu_info.flags & KVM_PPC_PAGE_SIZES_REAL) {
        env->ci_large_pages = getpagesize() >= 0x10000;
    }

    /*
     * XXX This loop should be an entry wide AND of the capabilities that
     *     the selected CPU has with the capabilities that KVM supports.
     */
    for (ik = iq = 0; ik < KVM_PPC_PAGE_SIZES_MAX_SZ; ik++) {
        struct ppc_one_seg_page_size *qsps = &env->sps.sps[iq];
        struct kvm_ppc_one_seg_page_size *ksps = &smmu_info.sps[ik];

        if (!kvm_valid_page_size(smmu_info.flags, max_cpu_page_size,
                                 ksps->page_shift)) {
            continue;
        }
        qsps->page_shift = ksps->page_shift;
        qsps->slb_enc = ksps->slb_enc;
        for (jk = jq = 0; jk < KVM_PPC_PAGE_SIZES_MAX_SZ; jk++) {
            if (!kvm_valid_page_size(smmu_info.flags, max_cpu_page_size,
                                     ksps->enc[jk].page_shift)) {
                continue;
            }
            if (ksps->enc[jk].page_shift == 16) {
                has_64k_pages = true;
            }
            qsps->enc[jq].page_shift = ksps->enc[jk].page_shift;
            qsps->enc[jq].pte_enc = ksps->enc[jk].pte_enc;
            if (++jq >= PPC_PAGE_SIZES_MAX_SZ) {
                break;
            }
        }
        if (++iq >= PPC_PAGE_SIZES_MAX_SZ) {
            break;
        }
    }
    env->slb_nr = smmu_info.slb_size;
    if (!(smmu_info.flags & KVM_PPC_1T_SEGMENTS)) {
        env->mmu_model &= ~POWERPC_MMU_1TSEG;
    }
    if (!has_64k_pages) {
        env->mmu_model &= ~POWERPC_MMU_64K;
    }
}

bool kvmppc_is_mem_backend_page_size_ok(char *obj_path)
{
    Object *mem_obj = object_resolve_path(obj_path, NULL);
    char *mempath = object_property_get_str(mem_obj, "mem-path", NULL);
    long pagesize;

    if (mempath) {
        pagesize = qemu_mempath_getpagesize(mempath);
    } else {
        pagesize = getpagesize();
    }

    return pagesize >= max_cpu_page_size;
}

#else /* defined (TARGET_PPC64) */

static inline void kvm_fixup_page_sizes(PowerPCCPU *cpu)
{
}

bool kvmppc_is_mem_backend_page_size_ok(char *obj_path)
{
    return true;
}

#endif /* !defined (TARGET_PPC64) */

unsigned long kvm_arch_vcpu_id(CPUState *cpu)
{
    return ppc_get_vcpu_dt_id(POWERPC_CPU(cpu));
}

/* e500 supports 2 h/w breakpoint and 2 watchpoint.
 * book3s supports only 1 watchpoint, so array size
 * of 4 is sufficient for now.
 */
#define MAX_HW_BKPTS 4

static struct HWBreakpoint {
    target_ulong addr;
    int type;
} hw_debug_points[MAX_HW_BKPTS];

static CPUWatchpoint hw_watchpoint;

/* Default there is no breakpoint and watchpoint supported */
static int max_hw_breakpoint;
static int max_hw_watchpoint;
static int nb_hw_breakpoint;
static int nb_hw_watchpoint;

static void kvmppc_hw_debug_points_init(CPUPPCState *cenv)
{
    if (cenv->excp_model == POWERPC_EXCP_BOOKE) {
        max_hw_breakpoint = 2;
        max_hw_watchpoint = 2;
    }

    if ((max_hw_breakpoint + max_hw_watchpoint) > MAX_HW_BKPTS) {
        fprintf(stderr, "Error initializing h/w breakpoints\n");
        return;
    }
}

int kvm_arch_init_vcpu(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *cenv = &cpu->env;
    int ret;

    /* Gather server mmu info from KVM and update the CPU state */
    kvm_fixup_page_sizes(cpu);

    /* Synchronize sregs with kvm */
    ret = kvm_arch_sync_sregs(cpu);
    if (ret) {
        if (ret == -EINVAL) {
            error_report("Register sync failed... If you're using kvm-hv.ko,"
                         " only \"-cpu host\" is possible");
        }
        return ret;
    }

    idle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, kvm_kick_cpu, cpu);

    switch (cenv->mmu_model) {
    case POWERPC_MMU_BOOKE206:
        /* This target supports access to KVM's guest TLB */
        ret = kvm_booke206_tlb_init(cpu);
        break;
    case POWERPC_MMU_2_07:
        if (!cap_htm && !kvmppc_is_pr(cs->kvm_state)) {
            /* KVM-HV has transactional memory on POWER8 also without the
             * KVM_CAP_PPC_HTM extension, so enable it here instead. */
            cap_htm = true;
        }
        break;
    default:
        break;
    }

    kvm_get_one_reg(cs, KVM_REG_PPC_DEBUG_INST, &debug_inst_opcode);
    kvmppc_hw_debug_points_init(cenv);

    return ret;
}

static void kvm_sw_tlb_put(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    struct kvm_dirty_tlb dirty_tlb;
    unsigned char *bitmap;
    int ret;

    if (!env->kvm_sw_tlb) {
        return;
    }

    bitmap = g_malloc((env->nb_tlb + 7) / 8);
    memset(bitmap, 0xFF, (env->nb_tlb + 7) / 8);

    dirty_tlb.bitmap = (uintptr_t)bitmap;
    dirty_tlb.num_dirty = env->nb_tlb;

    ret = kvm_vcpu_ioctl(cs, KVM_DIRTY_TLB, &dirty_tlb);
    if (ret) {
        fprintf(stderr, "%s: KVM_DIRTY_TLB: %s\n",
                __func__, strerror(-ret));
    }

    g_free(bitmap);
}

static void kvm_get_one_spr(CPUState *cs, uint64_t id, int spr)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    union {
        uint32_t u32;
        uint64_t u64;
    } val;
    struct kvm_one_reg reg = {
        .id = id,
        .addr = (uintptr_t) &val,
    };
    int ret;

    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret != 0) {
        trace_kvm_failed_spr_get(spr, strerror(errno));
    } else {
        switch (id & KVM_REG_SIZE_MASK) {
        case KVM_REG_SIZE_U32:
            env->spr[spr] = val.u32;
            break;

        case KVM_REG_SIZE_U64:
            env->spr[spr] = val.u64;
            break;

        default:
            /* Don't handle this size yet */
            abort();
        }
    }
}

static void kvm_put_one_spr(CPUState *cs, uint64_t id, int spr)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    union {
        uint32_t u32;
        uint64_t u64;
    } val;
    struct kvm_one_reg reg = {
        .id = id,
        .addr = (uintptr_t) &val,
    };
    int ret;

    switch (id & KVM_REG_SIZE_MASK) {
    case KVM_REG_SIZE_U32:
        val.u32 = env->spr[spr];
        break;

    case KVM_REG_SIZE_U64:
        val.u64 = env->spr[spr];
        break;

    default:
        /* Don't handle this size yet */
        abort();
    }

    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret != 0) {
        trace_kvm_failed_spr_set(spr, strerror(errno));
    }
}

static int kvm_put_fp(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_one_reg reg;
    int i;
    int ret;

    if (env->insns_flags & PPC_FLOAT) {
        uint64_t fpscr = env->fpscr;
        bool vsx = !!(env->insns_flags2 & PPC2_VSX);

        reg.id = KVM_REG_PPC_FPSCR;
        reg.addr = (uintptr_t)&fpscr;
        ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to set FPSCR to KVM: %s\n", strerror(errno));
            return ret;
        }

        for (i = 0; i < 32; i++) {
            uint64_t vsr[2];

#ifdef HOST_WORDS_BIGENDIAN
            vsr[0] = float64_val(env->fpr[i]);
            vsr[1] = env->vsr[i];
#else
            vsr[0] = env->vsr[i];
            vsr[1] = float64_val(env->fpr[i]);
#endif
            reg.addr = (uintptr_t) &vsr;
            reg.id = vsx ? KVM_REG_PPC_VSR(i) : KVM_REG_PPC_FPR(i);

            ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
            if (ret < 0) {
                DPRINTF("Unable to set %s%d to KVM: %s\n", vsx ? "VSR" : "FPR",
                        i, strerror(errno));
                return ret;
            }
        }
    }

    if (env->insns_flags & PPC_ALTIVEC) {
        reg.id = KVM_REG_PPC_VSCR;
        reg.addr = (uintptr_t)&env->vscr;
        ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to set VSCR to KVM: %s\n", strerror(errno));
            return ret;
        }

        for (i = 0; i < 32; i++) {
            reg.id = KVM_REG_PPC_VR(i);
            reg.addr = (uintptr_t)&env->avr[i];
            ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
            if (ret < 0) {
                DPRINTF("Unable to set VR%d to KVM: %s\n", i, strerror(errno));
                return ret;
            }
        }
    }

    return 0;
}

static int kvm_get_fp(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_one_reg reg;
    int i;
    int ret;

    if (env->insns_flags & PPC_FLOAT) {
        uint64_t fpscr;
        bool vsx = !!(env->insns_flags2 & PPC2_VSX);

        reg.id = KVM_REG_PPC_FPSCR;
        reg.addr = (uintptr_t)&fpscr;
        ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to get FPSCR from KVM: %s\n", strerror(errno));
            return ret;
        } else {
            env->fpscr = fpscr;
        }

        for (i = 0; i < 32; i++) {
            uint64_t vsr[2];

            reg.addr = (uintptr_t) &vsr;
            reg.id = vsx ? KVM_REG_PPC_VSR(i) : KVM_REG_PPC_FPR(i);

            ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
            if (ret < 0) {
                DPRINTF("Unable to get %s%d from KVM: %s\n",
                        vsx ? "VSR" : "FPR", i, strerror(errno));
                return ret;
            } else {
#ifdef HOST_WORDS_BIGENDIAN
                env->fpr[i] = vsr[0];
                if (vsx) {
                    env->vsr[i] = vsr[1];
                }
#else
                env->fpr[i] = vsr[1];
                if (vsx) {
                    env->vsr[i] = vsr[0];
                }
#endif
            }
        }
    }

    if (env->insns_flags & PPC_ALTIVEC) {
        reg.id = KVM_REG_PPC_VSCR;
        reg.addr = (uintptr_t)&env->vscr;
        ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to get VSCR from KVM: %s\n", strerror(errno));
            return ret;
        }

        for (i = 0; i < 32; i++) {
            reg.id = KVM_REG_PPC_VR(i);
            reg.addr = (uintptr_t)&env->avr[i];
            ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
            if (ret < 0) {
                DPRINTF("Unable to get VR%d from KVM: %s\n",
                        i, strerror(errno));
                return ret;
            }
        }
    }

    return 0;
}

#if defined(TARGET_PPC64)
static int kvm_get_vpa(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_one_reg reg;
    int ret;

    reg.id = KVM_REG_PPC_VPA_ADDR;
    reg.addr = (uintptr_t)&env->vpa_addr;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret < 0) {
        DPRINTF("Unable to get VPA address from KVM: %s\n", strerror(errno));
        return ret;
    }

    assert((uintptr_t)&env->slb_shadow_size
           == ((uintptr_t)&env->slb_shadow_addr + 8));
    reg.id = KVM_REG_PPC_VPA_SLB;
    reg.addr = (uintptr_t)&env->slb_shadow_addr;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret < 0) {
        DPRINTF("Unable to get SLB shadow state from KVM: %s\n",
                strerror(errno));
        return ret;
    }

    assert((uintptr_t)&env->dtl_size == ((uintptr_t)&env->dtl_addr + 8));
    reg.id = KVM_REG_PPC_VPA_DTL;
    reg.addr = (uintptr_t)&env->dtl_addr;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret < 0) {
        DPRINTF("Unable to get dispatch trace log state from KVM: %s\n",
                strerror(errno));
        return ret;
    }

    return 0;
}

static int kvm_put_vpa(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_one_reg reg;
    int ret;

    /* SLB shadow or DTL can't be registered unless a master VPA is
     * registered.  That means when restoring state, if a VPA *is*
     * registered, we need to set that up first.  If not, we need to
     * deregister the others before deregistering the master VPA */
    assert(env->vpa_addr || !(env->slb_shadow_addr || env->dtl_addr));

    if (env->vpa_addr) {
        reg.id = KVM_REG_PPC_VPA_ADDR;
        reg.addr = (uintptr_t)&env->vpa_addr;
        ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to set VPA address to KVM: %s\n", strerror(errno));
            return ret;
        }
    }

    assert((uintptr_t)&env->slb_shadow_size
           == ((uintptr_t)&env->slb_shadow_addr + 8));
    reg.id = KVM_REG_PPC_VPA_SLB;
    reg.addr = (uintptr_t)&env->slb_shadow_addr;
    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret < 0) {
        DPRINTF("Unable to set SLB shadow state to KVM: %s\n", strerror(errno));
        return ret;
    }

    assert((uintptr_t)&env->dtl_size == ((uintptr_t)&env->dtl_addr + 8));
    reg.id = KVM_REG_PPC_VPA_DTL;
    reg.addr = (uintptr_t)&env->dtl_addr;
    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret < 0) {
        DPRINTF("Unable to set dispatch trace log state to KVM: %s\n",
                strerror(errno));
        return ret;
    }

    if (!env->vpa_addr) {
        reg.id = KVM_REG_PPC_VPA_ADDR;
        reg.addr = (uintptr_t)&env->vpa_addr;
        ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
        if (ret < 0) {
            DPRINTF("Unable to set VPA address to KVM: %s\n", strerror(errno));
            return ret;
        }
    }

    return 0;
}
#endif /* TARGET_PPC64 */

int kvmppc_put_books_sregs(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    struct kvm_sregs sregs;
    int i;

    sregs.pvr = env->spr[SPR_PVR];

    sregs.u.s.sdr1 = env->spr[SPR_SDR1];

    /* Sync SLB */
#ifdef TARGET_PPC64
    for (i = 0; i < ARRAY_SIZE(env->slb); i++) {
        sregs.u.s.ppc64.slb[i].slbe = env->slb[i].esid;
        if (env->slb[i].esid & SLB_ESID_V) {
            sregs.u.s.ppc64.slb[i].slbe |= i;
        }
        sregs.u.s.ppc64.slb[i].slbv = env->slb[i].vsid;
    }
#endif

    /* Sync SRs */
    for (i = 0; i < 16; i++) {
        sregs.u.s.ppc32.sr[i] = env->sr[i];
    }

    /* Sync BATs */
    for (i = 0; i < 8; i++) {
        /* Beware. We have to swap upper and lower bits here */
        sregs.u.s.ppc32.dbat[i] = ((uint64_t)env->DBAT[0][i] << 32)
            | env->DBAT[1][i];
        sregs.u.s.ppc32.ibat[i] = ((uint64_t)env->IBAT[0][i] << 32)
            | env->IBAT[1][i];
    }

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_SREGS, &sregs);
}

int kvm_arch_put_registers(CPUState *cs, int level)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_regs regs;
    int ret;
    int i;

    ret = kvm_vcpu_ioctl(cs, KVM_GET_REGS, &regs);
    if (ret < 0) {
        return ret;
    }

    regs.ctr = env->ctr;
    regs.lr  = env->lr;
    regs.xer = cpu_read_xer(env);
    regs.msr = env->msr;
    regs.pc = env->nip;

    regs.srr0 = env->spr[SPR_SRR0];
    regs.srr1 = env->spr[SPR_SRR1];

    regs.sprg0 = env->spr[SPR_SPRG0];
    regs.sprg1 = env->spr[SPR_SPRG1];
    regs.sprg2 = env->spr[SPR_SPRG2];
    regs.sprg3 = env->spr[SPR_SPRG3];
    regs.sprg4 = env->spr[SPR_SPRG4];
    regs.sprg5 = env->spr[SPR_SPRG5];
    regs.sprg6 = env->spr[SPR_SPRG6];
    regs.sprg7 = env->spr[SPR_SPRG7];

    regs.pid = env->spr[SPR_BOOKE_PID];

    for (i = 0;i < 32; i++)
        regs.gpr[i] = env->gpr[i];

    regs.cr = 0;
    for (i = 0; i < 8; i++) {
        regs.cr |= (env->crf[i] & 15) << (4 * (7 - i));
    }

    ret = kvm_vcpu_ioctl(cs, KVM_SET_REGS, &regs);
    if (ret < 0)
        return ret;

    kvm_put_fp(cs);

    if (env->tlb_dirty) {
        kvm_sw_tlb_put(cpu);
        env->tlb_dirty = false;
    }

    if (cap_segstate && (level >= KVM_PUT_RESET_STATE)) {
        ret = kvmppc_put_books_sregs(cpu);
        if (ret < 0) {
            return ret;
        }
    }

    if (cap_hior && (level >= KVM_PUT_RESET_STATE)) {
        kvm_put_one_spr(cs, KVM_REG_PPC_HIOR, SPR_HIOR);
    }

    if (cap_one_reg) {
        int i;

        /* We deliberately ignore errors here, for kernels which have
         * the ONE_REG calls, but don't support the specific
         * registers, there's a reasonable chance things will still
         * work, at least until we try to migrate. */
        for (i = 0; i < 1024; i++) {
            uint64_t id = env->spr_cb[i].one_reg_id;

            if (id != 0) {
                kvm_put_one_spr(cs, id, i);
            }
        }

#ifdef TARGET_PPC64
        if (msr_ts) {
            for (i = 0; i < ARRAY_SIZE(env->tm_gpr); i++) {
                kvm_set_one_reg(cs, KVM_REG_PPC_TM_GPR(i), &env->tm_gpr[i]);
            }
            for (i = 0; i < ARRAY_SIZE(env->tm_vsr); i++) {
                kvm_set_one_reg(cs, KVM_REG_PPC_TM_VSR(i), &env->tm_vsr[i]);
            }
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_CR, &env->tm_cr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_LR, &env->tm_lr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_CTR, &env->tm_ctr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_FPSCR, &env->tm_fpscr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_AMR, &env->tm_amr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_PPR, &env->tm_ppr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_VRSAVE, &env->tm_vrsave);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_VSCR, &env->tm_vscr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_DSCR, &env->tm_dscr);
            kvm_set_one_reg(cs, KVM_REG_PPC_TM_TAR, &env->tm_tar);
        }

        if (cap_papr) {
            if (kvm_put_vpa(cs) < 0) {
                DPRINTF("Warning: Unable to set VPA information to KVM\n");
            }
        }

        kvm_set_one_reg(cs, KVM_REG_PPC_TB_OFFSET, &env->tb_env->tb_offset);
#endif /* TARGET_PPC64 */
    }

    return ret;
}

static void kvm_sync_excp(CPUPPCState *env, int vector, int ivor)
{
     env->excp_vectors[vector] = env->spr[ivor] + env->spr[SPR_BOOKE_IVPR];
}

static int kvmppc_get_booke_sregs(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    struct kvm_sregs sregs;
    int ret;

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_SREGS, &sregs);
    if (ret < 0) {
        return ret;
    }

    if (sregs.u.e.features & KVM_SREGS_E_BASE) {
        env->spr[SPR_BOOKE_CSRR0] = sregs.u.e.csrr0;
        env->spr[SPR_BOOKE_CSRR1] = sregs.u.e.csrr1;
        env->spr[SPR_BOOKE_ESR] = sregs.u.e.esr;
        env->spr[SPR_BOOKE_DEAR] = sregs.u.e.dear;
        env->spr[SPR_BOOKE_MCSR] = sregs.u.e.mcsr;
        env->spr[SPR_BOOKE_TSR] = sregs.u.e.tsr;
        env->spr[SPR_BOOKE_TCR] = sregs.u.e.tcr;
        env->spr[SPR_DECR] = sregs.u.e.dec;
        env->spr[SPR_TBL] = sregs.u.e.tb & 0xffffffff;
        env->spr[SPR_TBU] = sregs.u.e.tb >> 32;
        env->spr[SPR_VRSAVE] = sregs.u.e.vrsave;
    }

    if (sregs.u.e.features & KVM_SREGS_E_ARCH206) {
        env->spr[SPR_BOOKE_PIR] = sregs.u.e.pir;
        env->spr[SPR_BOOKE_MCSRR0] = sregs.u.e.mcsrr0;
        env->spr[SPR_BOOKE_MCSRR1] = sregs.u.e.mcsrr1;
        env->spr[SPR_BOOKE_DECAR] = sregs.u.e.decar;
        env->spr[SPR_BOOKE_IVPR] = sregs.u.e.ivpr;
    }

    if (sregs.u.e.features & KVM_SREGS_E_64) {
        env->spr[SPR_BOOKE_EPCR] = sregs.u.e.epcr;
    }

    if (sregs.u.e.features & KVM_SREGS_E_SPRG8) {
        env->spr[SPR_BOOKE_SPRG8] = sregs.u.e.sprg8;
    }

    if (sregs.u.e.features & KVM_SREGS_E_IVOR) {
        env->spr[SPR_BOOKE_IVOR0] = sregs.u.e.ivor_low[0];
        kvm_sync_excp(env, POWERPC_EXCP_CRITICAL,  SPR_BOOKE_IVOR0);
        env->spr[SPR_BOOKE_IVOR1] = sregs.u.e.ivor_low[1];
        kvm_sync_excp(env, POWERPC_EXCP_MCHECK,  SPR_BOOKE_IVOR1);
        env->spr[SPR_BOOKE_IVOR2] = sregs.u.e.ivor_low[2];
        kvm_sync_excp(env, POWERPC_EXCP_DSI,  SPR_BOOKE_IVOR2);
        env->spr[SPR_BOOKE_IVOR3] = sregs.u.e.ivor_low[3];
        kvm_sync_excp(env, POWERPC_EXCP_ISI,  SPR_BOOKE_IVOR3);
        env->spr[SPR_BOOKE_IVOR4] = sregs.u.e.ivor_low[4];
        kvm_sync_excp(env, POWERPC_EXCP_EXTERNAL,  SPR_BOOKE_IVOR4);
        env->spr[SPR_BOOKE_IVOR5] = sregs.u.e.ivor_low[5];
        kvm_sync_excp(env, POWERPC_EXCP_ALIGN,  SPR_BOOKE_IVOR5);
        env->spr[SPR_BOOKE_IVOR6] = sregs.u.e.ivor_low[6];
        kvm_sync_excp(env, POWERPC_EXCP_PROGRAM,  SPR_BOOKE_IVOR6);
        env->spr[SPR_BOOKE_IVOR7] = sregs.u.e.ivor_low[7];
        kvm_sync_excp(env, POWERPC_EXCP_FPU,  SPR_BOOKE_IVOR7);
        env->spr[SPR_BOOKE_IVOR8] = sregs.u.e.ivor_low[8];
        kvm_sync_excp(env, POWERPC_EXCP_SYSCALL,  SPR_BOOKE_IVOR8);
        env->spr[SPR_BOOKE_IVOR9] = sregs.u.e.ivor_low[9];
        kvm_sync_excp(env, POWERPC_EXCP_APU,  SPR_BOOKE_IVOR9);
        env->spr[SPR_BOOKE_IVOR10] = sregs.u.e.ivor_low[10];
        kvm_sync_excp(env, POWERPC_EXCP_DECR,  SPR_BOOKE_IVOR10);
        env->spr[SPR_BOOKE_IVOR11] = sregs.u.e.ivor_low[11];
        kvm_sync_excp(env, POWERPC_EXCP_FIT,  SPR_BOOKE_IVOR11);
        env->spr[SPR_BOOKE_IVOR12] = sregs.u.e.ivor_low[12];
        kvm_sync_excp(env, POWERPC_EXCP_WDT,  SPR_BOOKE_IVOR12);
        env->spr[SPR_BOOKE_IVOR13] = sregs.u.e.ivor_low[13];
        kvm_sync_excp(env, POWERPC_EXCP_DTLB,  SPR_BOOKE_IVOR13);
        env->spr[SPR_BOOKE_IVOR14] = sregs.u.e.ivor_low[14];
        kvm_sync_excp(env, POWERPC_EXCP_ITLB,  SPR_BOOKE_IVOR14);
        env->spr[SPR_BOOKE_IVOR15] = sregs.u.e.ivor_low[15];
        kvm_sync_excp(env, POWERPC_EXCP_DEBUG,  SPR_BOOKE_IVOR15);

        if (sregs.u.e.features & KVM_SREGS_E_SPE) {
            env->spr[SPR_BOOKE_IVOR32] = sregs.u.e.ivor_high[0];
            kvm_sync_excp(env, POWERPC_EXCP_SPEU,  SPR_BOOKE_IVOR32);
            env->spr[SPR_BOOKE_IVOR33] = sregs.u.e.ivor_high[1];
            kvm_sync_excp(env, POWERPC_EXCP_EFPDI,  SPR_BOOKE_IVOR33);
            env->spr[SPR_BOOKE_IVOR34] = sregs.u.e.ivor_high[2];
            kvm_sync_excp(env, POWERPC_EXCP_EFPRI,  SPR_BOOKE_IVOR34);
        }

        if (sregs.u.e.features & KVM_SREGS_E_PM) {
            env->spr[SPR_BOOKE_IVOR35] = sregs.u.e.ivor_high[3];
            kvm_sync_excp(env, POWERPC_EXCP_EPERFM,  SPR_BOOKE_IVOR35);
        }

        if (sregs.u.e.features & KVM_SREGS_E_PC) {
            env->spr[SPR_BOOKE_IVOR36] = sregs.u.e.ivor_high[4];
            kvm_sync_excp(env, POWERPC_EXCP_DOORI,  SPR_BOOKE_IVOR36);
            env->spr[SPR_BOOKE_IVOR37] = sregs.u.e.ivor_high[5];
            kvm_sync_excp(env, POWERPC_EXCP_DOORCI, SPR_BOOKE_IVOR37);
        }
    }

    if (sregs.u.e.features & KVM_SREGS_E_ARCH206_MMU) {
        env->spr[SPR_BOOKE_MAS0] = sregs.u.e.mas0;
        env->spr[SPR_BOOKE_MAS1] = sregs.u.e.mas1;
        env->spr[SPR_BOOKE_MAS2] = sregs.u.e.mas2;
        env->spr[SPR_BOOKE_MAS3] = sregs.u.e.mas7_3 & 0xffffffff;
        env->spr[SPR_BOOKE_MAS4] = sregs.u.e.mas4;
        env->spr[SPR_BOOKE_MAS6] = sregs.u.e.mas6;
        env->spr[SPR_BOOKE_MAS7] = sregs.u.e.mas7_3 >> 32;
        env->spr[SPR_MMUCFG] = sregs.u.e.mmucfg;
        env->spr[SPR_BOOKE_TLB0CFG] = sregs.u.e.tlbcfg[0];
        env->spr[SPR_BOOKE_TLB1CFG] = sregs.u.e.tlbcfg[1];
    }

    if (sregs.u.e.features & KVM_SREGS_EXP) {
        env->spr[SPR_BOOKE_EPR] = sregs.u.e.epr;
    }

    if (sregs.u.e.features & KVM_SREGS_E_PD) {
        env->spr[SPR_BOOKE_EPLC] = sregs.u.e.eplc;
        env->spr[SPR_BOOKE_EPSC] = sregs.u.e.epsc;
    }

    if (sregs.u.e.impl_id == KVM_SREGS_E_IMPL_FSL) {
        env->spr[SPR_E500_SVR] = sregs.u.e.impl.fsl.svr;
        env->spr[SPR_Exxx_MCAR] = sregs.u.e.impl.fsl.mcar;
        env->spr[SPR_HID0] = sregs.u.e.impl.fsl.hid0;

        if (sregs.u.e.impl.fsl.features & KVM_SREGS_E_FSL_PIDn) {
            env->spr[SPR_BOOKE_PID1] = sregs.u.e.impl.fsl.pid1;
            env->spr[SPR_BOOKE_PID2] = sregs.u.e.impl.fsl.pid2;
        }
    }

    return 0;
}

static int kvmppc_get_books_sregs(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    struct kvm_sregs sregs;
    int ret;
    int i;

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_SREGS, &sregs);
    if (ret < 0) {
        return ret;
    }

    if (!cpu->vhyp) {
        ppc_store_sdr1(env, sregs.u.s.sdr1);
    }

    /* Sync SLB */
#ifdef TARGET_PPC64
    /*
     * The packed SLB array we get from KVM_GET_SREGS only contains
     * information about valid entries. So we flush our internal copy
     * to get rid of stale ones, then put all valid SLB entries back
     * in.
     */
    memset(env->slb, 0, sizeof(env->slb));
    for (i = 0; i < ARRAY_SIZE(env->slb); i++) {
        target_ulong rb = sregs.u.s.ppc64.slb[i].slbe;
        target_ulong rs = sregs.u.s.ppc64.slb[i].slbv;
        /*
         * Only restore valid entries
         */
        if (rb & SLB_ESID_V) {
            ppc_store_slb(cpu, rb & 0xfff, rb & ~0xfffULL, rs);
        }
    }
#endif

    /* Sync SRs */
    for (i = 0; i < 16; i++) {
        env->sr[i] = sregs.u.s.ppc32.sr[i];
    }

    /* Sync BATs */
    for (i = 0; i < 8; i++) {
        env->DBAT[0][i] = sregs.u.s.ppc32.dbat[i] & 0xffffffff;
        env->DBAT[1][i] = sregs.u.s.ppc32.dbat[i] >> 32;
        env->IBAT[0][i] = sregs.u.s.ppc32.ibat[i] & 0xffffffff;
        env->IBAT[1][i] = sregs.u.s.ppc32.ibat[i] >> 32;
    }

    return 0;
}

int kvm_arch_get_registers(CPUState *cs)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    struct kvm_regs regs;
    uint32_t cr;
    int i, ret;

    ret = kvm_vcpu_ioctl(cs, KVM_GET_REGS, &regs);
    if (ret < 0)
        return ret;

    cr = regs.cr;
    for (i = 7; i >= 0; i--) {
        env->crf[i] = cr & 15;
        cr >>= 4;
    }

    env->ctr = regs.ctr;
    env->lr = regs.lr;
    cpu_write_xer(env, regs.xer);
    env->msr = regs.msr;
    env->nip = regs.pc;

    env->spr[SPR_SRR0] = regs.srr0;
    env->spr[SPR_SRR1] = regs.srr1;

    env->spr[SPR_SPRG0] = regs.sprg0;
    env->spr[SPR_SPRG1] = regs.sprg1;
    env->spr[SPR_SPRG2] = regs.sprg2;
    env->spr[SPR_SPRG3] = regs.sprg3;
    env->spr[SPR_SPRG4] = regs.sprg4;
    env->spr[SPR_SPRG5] = regs.sprg5;
    env->spr[SPR_SPRG6] = regs.sprg6;
    env->spr[SPR_SPRG7] = regs.sprg7;

    env->spr[SPR_BOOKE_PID] = regs.pid;

    for (i = 0;i < 32; i++)
        env->gpr[i] = regs.gpr[i];

    kvm_get_fp(cs);

    if (cap_booke_sregs) {
        ret = kvmppc_get_booke_sregs(cpu);
        if (ret < 0) {
            return ret;
        }
    }

    if (cap_segstate) {
        ret = kvmppc_get_books_sregs(cpu);
        if (ret < 0) {
            return ret;
        }
    }

    if (cap_hior) {
        kvm_get_one_spr(cs, KVM_REG_PPC_HIOR, SPR_HIOR);
    }

    if (cap_one_reg) {
        int i;

        /* We deliberately ignore errors here, for kernels which have
         * the ONE_REG calls, but don't support the specific
         * registers, there's a reasonable chance things will still
         * work, at least until we try to migrate. */
        for (i = 0; i < 1024; i++) {
            uint64_t id = env->spr_cb[i].one_reg_id;

            if (id != 0) {
                kvm_get_one_spr(cs, id, i);
            }
        }

#ifdef TARGET_PPC64
        if (msr_ts) {
            for (i = 0; i < ARRAY_SIZE(env->tm_gpr); i++) {
                kvm_get_one_reg(cs, KVM_REG_PPC_TM_GPR(i), &env->tm_gpr[i]);
            }
            for (i = 0; i < ARRAY_SIZE(env->tm_vsr); i++) {
                kvm_get_one_reg(cs, KVM_REG_PPC_TM_VSR(i), &env->tm_vsr[i]);
            }
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_CR, &env->tm_cr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_LR, &env->tm_lr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_CTR, &env->tm_ctr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_FPSCR, &env->tm_fpscr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_AMR, &env->tm_amr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_PPR, &env->tm_ppr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_VRSAVE, &env->tm_vrsave);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_VSCR, &env->tm_vscr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_DSCR, &env->tm_dscr);
            kvm_get_one_reg(cs, KVM_REG_PPC_TM_TAR, &env->tm_tar);
        }

        if (cap_papr) {
            if (kvm_get_vpa(cs) < 0) {
                DPRINTF("Warning: Unable to get VPA information from KVM\n");
            }
        }

        kvm_get_one_reg(cs, KVM_REG_PPC_TB_OFFSET, &env->tb_env->tb_offset);
#endif
    }

    return 0;
}

int kvmppc_set_interrupt(PowerPCCPU *cpu, int irq, int level)
{
    unsigned virq = level ? KVM_INTERRUPT_SET_LEVEL : KVM_INTERRUPT_UNSET;

    if (irq != PPC_INTERRUPT_EXT) {
        return 0;
    }

    if (!kvm_enabled() || !cap_interrupt_unset || !cap_interrupt_level) {
        return 0;
    }

    kvm_vcpu_ioctl(CPU(cpu), KVM_INTERRUPT, &virq);

    return 0;
}

#if defined(TARGET_PPCEMB)
#define PPC_INPUT_INT PPC40x_INPUT_INT
#elif defined(TARGET_PPC64)
#define PPC_INPUT_INT PPC970_INPUT_INT
#else
#define PPC_INPUT_INT PPC6xx_INPUT_INT
#endif

void kvm_arch_pre_run(CPUState *cs, struct kvm_run *run)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    int r;
    unsigned irq;

    qemu_mutex_lock_iothread();

    /* PowerPC QEMU tracks the various core input pins (interrupt, critical
     * interrupt, reset, etc) in PPC-specific env->irq_input_state. */
    if (!cap_interrupt_level &&
        run->ready_for_interrupt_injection &&
        (cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        (env->irq_input_state & (1<<PPC_INPUT_INT)))
    {
        /* For now KVM disregards the 'irq' argument. However, in the
         * future KVM could cache it in-kernel to avoid a heavyweight exit
         * when reading the UIC.
         */
        irq = KVM_INTERRUPT_SET;

        DPRINTF("injected interrupt %d\n", irq);
        r = kvm_vcpu_ioctl(cs, KVM_INTERRUPT, &irq);
        if (r < 0) {
            printf("cpu %d fail inject %x\n", cs->cpu_index, irq);
        }

        /* Always wake up soon in case the interrupt was level based */
        timer_mod(idle_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                       (NANOSECONDS_PER_SECOND / 50));
    }

    /* We don't know if there are more interrupts pending after this. However,
     * the guest will return to userspace in the course of handling this one
     * anyways, so we will get a chance to deliver the rest. */

    qemu_mutex_unlock_iothread();
}

MemTxAttrs kvm_arch_post_run(CPUState *cs, struct kvm_run *run)
{
    return MEMTXATTRS_UNSPECIFIED;
}

int kvm_arch_process_async_events(CPUState *cs)
{
    return cs->halted;
}

static int kvmppc_handle_halt(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;

    if (!(cs->interrupt_request & CPU_INTERRUPT_HARD) && (msr_ee)) {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
    }

    return 0;
}

/* map dcr access to existing qemu dcr emulation */
static int kvmppc_handle_dcr_read(CPUPPCState *env, uint32_t dcrn, uint32_t *data)
{
    if (ppc_dcr_read(env->dcr_env, dcrn, data) < 0)
        fprintf(stderr, "Read to unhandled DCR (0x%x)\n", dcrn);

    return 0;
}

static int kvmppc_handle_dcr_write(CPUPPCState *env, uint32_t dcrn, uint32_t data)
{
    if (ppc_dcr_write(env->dcr_env, dcrn, data) < 0)
        fprintf(stderr, "Write to unhandled DCR (0x%x)\n", dcrn);

    return 0;
}

int kvm_arch_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    /* Mixed endian case is not handled */
    uint32_t sc = debug_inst_opcode;

    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn,
                            sizeof(sc), 0) ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&sc, sizeof(sc), 1)) {
        return -EINVAL;
    }

    return 0;
}

int kvm_arch_remove_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    uint32_t sc;

    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&sc, sizeof(sc), 0) ||
        sc != debug_inst_opcode ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn,
                            sizeof(sc), 1)) {
        return -EINVAL;
    }

    return 0;
}

static int find_hw_breakpoint(target_ulong addr, int type)
{
    int n;

    assert((nb_hw_breakpoint + nb_hw_watchpoint)
           <= ARRAY_SIZE(hw_debug_points));

    for (n = 0; n < nb_hw_breakpoint + nb_hw_watchpoint; n++) {
        if (hw_debug_points[n].addr == addr &&
             hw_debug_points[n].type == type) {
            return n;
        }
    }

    return -1;
}

static int find_hw_watchpoint(target_ulong addr, int *flag)
{
    int n;

    n = find_hw_breakpoint(addr, GDB_WATCHPOINT_ACCESS);
    if (n >= 0) {
        *flag = BP_MEM_ACCESS;
        return n;
    }

    n = find_hw_breakpoint(addr, GDB_WATCHPOINT_WRITE);
    if (n >= 0) {
        *flag = BP_MEM_WRITE;
        return n;
    }

    n = find_hw_breakpoint(addr, GDB_WATCHPOINT_READ);
    if (n >= 0) {
        *flag = BP_MEM_READ;
        return n;
    }

    return -1;
}

int kvm_arch_insert_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    if ((nb_hw_breakpoint + nb_hw_watchpoint) >= ARRAY_SIZE(hw_debug_points)) {
        return -ENOBUFS;
    }

    hw_debug_points[nb_hw_breakpoint + nb_hw_watchpoint].addr = addr;
    hw_debug_points[nb_hw_breakpoint + nb_hw_watchpoint].type = type;

    switch (type) {
    case GDB_BREAKPOINT_HW:
        if (nb_hw_breakpoint >= max_hw_breakpoint) {
            return -ENOBUFS;
        }

        if (find_hw_breakpoint(addr, type) >= 0) {
            return -EEXIST;
        }

        nb_hw_breakpoint++;
        break;

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        if (nb_hw_watchpoint >= max_hw_watchpoint) {
            return -ENOBUFS;
        }

        if (find_hw_breakpoint(addr, type) >= 0) {
            return -EEXIST;
        }

        nb_hw_watchpoint++;
        break;

    default:
        return -ENOSYS;
    }

    return 0;
}

int kvm_arch_remove_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    int n;

    n = find_hw_breakpoint(addr, type);
    if (n < 0) {
        return -ENOENT;
    }

    switch (type) {
    case GDB_BREAKPOINT_HW:
        nb_hw_breakpoint--;
        break;

    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_READ:
    case GDB_WATCHPOINT_ACCESS:
        nb_hw_watchpoint--;
        break;

    default:
        return -ENOSYS;
    }
    hw_debug_points[n] = hw_debug_points[nb_hw_breakpoint + nb_hw_watchpoint];

    return 0;
}

void kvm_arch_remove_all_hw_breakpoints(void)
{
    nb_hw_breakpoint = nb_hw_watchpoint = 0;
}

void kvm_arch_update_guest_debug(CPUState *cs, struct kvm_guest_debug *dbg)
{
    int n;

    /* Software Breakpoint updates */
    if (kvm_sw_breakpoints_active(cs)) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }

    assert((nb_hw_breakpoint + nb_hw_watchpoint)
           <= ARRAY_SIZE(hw_debug_points));
    assert((nb_hw_breakpoint + nb_hw_watchpoint) <= ARRAY_SIZE(dbg->arch.bp));

    if (nb_hw_breakpoint + nb_hw_watchpoint > 0) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        memset(dbg->arch.bp, 0, sizeof(dbg->arch.bp));
        for (n = 0; n < nb_hw_breakpoint + nb_hw_watchpoint; n++) {
            switch (hw_debug_points[n].type) {
            case GDB_BREAKPOINT_HW:
                dbg->arch.bp[n].type = KVMPPC_DEBUG_BREAKPOINT;
                break;
            case GDB_WATCHPOINT_WRITE:
                dbg->arch.bp[n].type = KVMPPC_DEBUG_WATCH_WRITE;
                break;
            case GDB_WATCHPOINT_READ:
                dbg->arch.bp[n].type = KVMPPC_DEBUG_WATCH_READ;
                break;
            case GDB_WATCHPOINT_ACCESS:
                dbg->arch.bp[n].type = KVMPPC_DEBUG_WATCH_WRITE |
                                        KVMPPC_DEBUG_WATCH_READ;
                break;
            default:
                cpu_abort(cs, "Unsupported breakpoint type\n");
            }
            dbg->arch.bp[n].addr = hw_debug_points[n].addr;
        }
    }
}

static int kvm_handle_debug(PowerPCCPU *cpu, struct kvm_run *run)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    struct kvm_debug_exit_arch *arch_info = &run->debug.arch;
    int handle = 0;
    int n;
    int flag = 0;

    if (cs->singlestep_enabled) {
        handle = 1;
    } else if (arch_info->status) {
        if (nb_hw_breakpoint + nb_hw_watchpoint > 0) {
            if (arch_info->status & KVMPPC_DEBUG_BREAKPOINT) {
                n = find_hw_breakpoint(arch_info->address, GDB_BREAKPOINT_HW);
                if (n >= 0) {
                    handle = 1;
                }
            } else if (arch_info->status & (KVMPPC_DEBUG_WATCH_READ |
                                            KVMPPC_DEBUG_WATCH_WRITE)) {
                n = find_hw_watchpoint(arch_info->address,  &flag);
                if (n >= 0) {
                    handle = 1;
                    cs->watchpoint_hit = &hw_watchpoint;
                    hw_watchpoint.vaddr = hw_debug_points[n].addr;
                    hw_watchpoint.flags = flag;
                }
            }
        }
    } else if (kvm_find_sw_breakpoint(cs, arch_info->address)) {
        handle = 1;
    } else {
        /* QEMU is not able to handle debug exception, so inject
         * program exception to guest;
         * Yes program exception NOT debug exception !!
         * When QEMU is using debug resources then debug exception must
         * be always set. To achieve this we set MSR_DE and also set
         * MSRP_DEP so guest cannot change MSR_DE.
         * When emulating debug resource for guest we want guest
         * to control MSR_DE (enable/disable debug interrupt on need).
         * Supporting both configurations are NOT possible.
         * So the result is that we cannot share debug resources
         * between QEMU and Guest on BOOKE architecture.
         * In the current design QEMU gets the priority over guest,
         * this means that if QEMU is using debug resources then guest
         * cannot use them;
         * For software breakpoint QEMU uses a privileged instruction;
         * So there cannot be any reason that we are here for guest
         * set debug exception, only possibility is guest executed a
         * privileged / illegal instruction and that's why we are
         * injecting a program interrupt.
         */

        cpu_synchronize_state(cs);
        /* env->nip is PC, so increment this by 4 to use
         * ppc_cpu_do_interrupt(), which set srr0 = env->nip - 4.
         */
        env->nip += 4;
        cs->exception_index = POWERPC_EXCP_PROGRAM;
        env->error_code = POWERPC_EXCP_INVAL;
        ppc_cpu_do_interrupt(cs);
    }

    return handle;
}

int kvm_arch_handle_exit(CPUState *cs, struct kvm_run *run)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;
    int ret;

    qemu_mutex_lock_iothread();

    switch (run->exit_reason) {
    case KVM_EXIT_DCR:
        if (run->dcr.is_write) {
            DPRINTF("handle dcr write\n");
            ret = kvmppc_handle_dcr_write(env, run->dcr.dcrn, run->dcr.data);
        } else {
            DPRINTF("handle dcr read\n");
            ret = kvmppc_handle_dcr_read(env, run->dcr.dcrn, &run->dcr.data);
        }
        break;
    case KVM_EXIT_HLT:
        DPRINTF("handle halt\n");
        ret = kvmppc_handle_halt(cpu);
        break;
#if defined(TARGET_PPC64)
    case KVM_EXIT_PAPR_HCALL:
        DPRINTF("handle PAPR hypercall\n");
        run->papr_hcall.ret = spapr_hypercall(cpu,
                                              run->papr_hcall.nr,
                                              run->papr_hcall.args);
        ret = 0;
        break;
#endif
    case KVM_EXIT_EPR:
        DPRINTF("handle epr\n");
        run->epr.epr = ldl_phys(cs->as, env->mpic_iack);
        ret = 0;
        break;
    case KVM_EXIT_WATCHDOG:
        DPRINTF("handle watchdog expiry\n");
        watchdog_perform_action();
        ret = 0;
        break;

    case KVM_EXIT_DEBUG:
        DPRINTF("handle debug exception\n");
        if (kvm_handle_debug(cpu, run)) {
            ret = EXCP_DEBUG;
            break;
        }
        /* re-enter, this exception was guest-internal */
        ret = 0;
        break;

    default:
        fprintf(stderr, "KVM: unknown exit reason %d\n", run->exit_reason);
        ret = -1;
        break;
    }

    qemu_mutex_unlock_iothread();
    return ret;
}

int kvmppc_or_tsr_bits(PowerPCCPU *cpu, uint32_t tsr_bits)
{
    CPUState *cs = CPU(cpu);
    uint32_t bits = tsr_bits;
    struct kvm_one_reg reg = {
        .id = KVM_REG_PPC_OR_TSR,
        .addr = (uintptr_t) &bits,
    };

    return kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
}

int kvmppc_clear_tsr_bits(PowerPCCPU *cpu, uint32_t tsr_bits)
{

    CPUState *cs = CPU(cpu);
    uint32_t bits = tsr_bits;
    struct kvm_one_reg reg = {
        .id = KVM_REG_PPC_CLEAR_TSR,
        .addr = (uintptr_t) &bits,
    };

    return kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
}

int kvmppc_set_tcr(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUPPCState *env = &cpu->env;
    uint32_t tcr = env->spr[SPR_BOOKE_TCR];

    struct kvm_one_reg reg = {
        .id = KVM_REG_PPC_TCR,
        .addr = (uintptr_t) &tcr,
    };

    return kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
}

int kvmppc_booke_watchdog_enable(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    int ret;

    if (!kvm_enabled()) {
        return -1;
    }

    if (!cap_ppc_watchdog) {
        printf("warning: KVM does not support watchdog");
        return -1;
    }

    ret = kvm_vcpu_enable_cap(cs, KVM_CAP_PPC_BOOKE_WATCHDOG, 0);
    if (ret < 0) {
        fprintf(stderr, "%s: couldn't enable KVM_CAP_PPC_BOOKE_WATCHDOG: %s\n",
                __func__, strerror(-ret));
        return ret;
    }

    return ret;
}

static int read_cpuinfo(const char *field, char *value, int len)
{
    FILE *f;
    int ret = -1;
    int field_len = strlen(field);
    char line[512];

    f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        return -1;
    }

    do {
        if (!fgets(line, sizeof(line), f)) {
            break;
        }
        if (!strncmp(line, field, field_len)) {
            pstrcpy(value, len, line);
            ret = 0;
            break;
        }
    } while(*line);

    fclose(f);

    return ret;
}

uint32_t kvmppc_get_tbfreq(void)
{
    char line[512];
    char *ns;
    uint32_t retval = NANOSECONDS_PER_SECOND;

    if (read_cpuinfo("timebase", line, sizeof(line))) {
        return retval;
    }

    if (!(ns = strchr(line, ':'))) {
        return retval;
    }

    ns++;

    return atoi(ns);
}

bool kvmppc_get_host_serial(char **value)
{
    return g_file_get_contents("/proc/device-tree/system-id", value, NULL,
                               NULL);
}

bool kvmppc_get_host_model(char **value)
{
    return g_file_get_contents("/proc/device-tree/model", value, NULL, NULL);
}

/* Try to find a device tree node for a CPU with clock-frequency property */
static int kvmppc_find_cpu_dt(char *buf, int buf_len)
{
    struct dirent *dirp;
    DIR *dp;

    if ((dp = opendir(PROC_DEVTREE_CPU)) == NULL) {
        printf("Can't open directory " PROC_DEVTREE_CPU "\n");
        return -1;
    }

    buf[0] = '\0';
    while ((dirp = readdir(dp)) != NULL) {
        FILE *f;
        snprintf(buf, buf_len, "%s%s/clock-frequency", PROC_DEVTREE_CPU,
                 dirp->d_name);
        f = fopen(buf, "r");
        if (f) {
            snprintf(buf, buf_len, "%s%s", PROC_DEVTREE_CPU, dirp->d_name);
            fclose(f);
            break;
        }
        buf[0] = '\0';
    }
    closedir(dp);
    if (buf[0] == '\0') {
        printf("Unknown host!\n");
        return -1;
    }

    return 0;
}

static uint64_t kvmppc_read_int_dt(const char *filename)
{
    union {
        uint32_t v32;
        uint64_t v64;
    } u;
    FILE *f;
    int len;

    f = fopen(filename, "rb");
    if (!f) {
        return -1;
    }

    len = fread(&u, 1, sizeof(u), f);
    fclose(f);
    switch (len) {
    case 4:
        /* property is a 32-bit quantity */
        return be32_to_cpu(u.v32);
    case 8:
        return be64_to_cpu(u.v64);
    }

    return 0;
}

/* Read a CPU node property from the host device tree that's a single
 * integer (32-bit or 64-bit).  Returns 0 if anything goes wrong
 * (can't find or open the property, or doesn't understand the
 * format) */
static uint64_t kvmppc_read_int_cpu_dt(const char *propname)
{
    char buf[PATH_MAX], *tmp;
    uint64_t val;

    if (kvmppc_find_cpu_dt(buf, sizeof(buf))) {
        return -1;
    }

    tmp = g_strdup_printf("%s/%s", buf, propname);
    val = kvmppc_read_int_dt(tmp);
    g_free(tmp);

    return val;
}

uint64_t kvmppc_get_clockfreq(void)
{
    return kvmppc_read_int_cpu_dt("clock-frequency");
}

uint32_t kvmppc_get_vmx(void)
{
    return kvmppc_read_int_cpu_dt("ibm,vmx");
}

uint32_t kvmppc_get_dfp(void)
{
    return kvmppc_read_int_cpu_dt("ibm,dfp");
}

static int kvmppc_get_pvinfo(CPUPPCState *env, struct kvm_ppc_pvinfo *pvinfo)
 {
     PowerPCCPU *cpu = ppc_env_get_cpu(env);
     CPUState *cs = CPU(cpu);

    if (kvm_vm_check_extension(cs->kvm_state, KVM_CAP_PPC_GET_PVINFO) &&
        !kvm_vm_ioctl(cs->kvm_state, KVM_PPC_GET_PVINFO, pvinfo)) {
        return 0;
    }

    return 1;
}

int kvmppc_get_hasidle(CPUPPCState *env)
{
    struct kvm_ppc_pvinfo pvinfo;

    if (!kvmppc_get_pvinfo(env, &pvinfo) &&
        (pvinfo.flags & KVM_PPC_PVINFO_FLAGS_EV_IDLE)) {
        return 1;
    }

    return 0;
}

int kvmppc_get_hypercall(CPUPPCState *env, uint8_t *buf, int buf_len)
{
    uint32_t *hc = (uint32_t*)buf;
    struct kvm_ppc_pvinfo pvinfo;

    if (!kvmppc_get_pvinfo(env, &pvinfo)) {
        memcpy(buf, pvinfo.hcall, buf_len);
        return 0;
    }

    /*
     * Fallback to always fail hypercalls regardless of endianness:
     *
     *     tdi 0,r0,72 (becomes b .+8 in wrong endian, nop in good endian)
     *     li r3, -1
     *     b .+8       (becomes nop in wrong endian)
     *     bswap32(li r3, -1)
     */

    hc[0] = cpu_to_be32(0x08000048);
    hc[1] = cpu_to_be32(0x3860ffff);
    hc[2] = cpu_to_be32(0x48000008);
    hc[3] = cpu_to_be32(bswap32(0x3860ffff));

    return 1;
}

static inline int kvmppc_enable_hcall(KVMState *s, target_ulong hcall)
{
    return kvm_vm_enable_cap(s, KVM_CAP_PPC_ENABLE_HCALL, 0, hcall, 1);
}

void kvmppc_enable_logical_ci_hcalls(void)
{
    /*
     * FIXME: it would be nice if we could detect the cases where
     * we're using a device which requires the in kernel
     * implementation of these hcalls, but the kernel lacks them and
     * produce a warning.
     */
    kvmppc_enable_hcall(kvm_state, H_LOGICAL_CI_LOAD);
    kvmppc_enable_hcall(kvm_state, H_LOGICAL_CI_STORE);
}

void kvmppc_enable_set_mode_hcall(void)
{
    kvmppc_enable_hcall(kvm_state, H_SET_MODE);
}

void kvmppc_enable_clear_ref_mod_hcalls(void)
{
    kvmppc_enable_hcall(kvm_state, H_CLEAR_REF);
    kvmppc_enable_hcall(kvm_state, H_CLEAR_MOD);
}

void kvmppc_set_papr(PowerPCCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    int ret;

    ret = kvm_vcpu_enable_cap(cs, KVM_CAP_PPC_PAPR, 0);
    if (ret) {
        error_report("This vCPU type or KVM version does not support PAPR");
        exit(1);
    }

    /* Update the capability flag so we sync the right information
     * with kvm */
    cap_papr = 1;
}

int kvmppc_set_compat(PowerPCCPU *cpu, uint32_t compat_pvr)
{
    return kvm_set_one_reg(CPU(cpu), KVM_REG_PPC_ARCH_COMPAT, &compat_pvr);
}

void kvmppc_set_mpic_proxy(PowerPCCPU *cpu, int mpic_proxy)
{
    CPUState *cs = CPU(cpu);
    int ret;

    ret = kvm_vcpu_enable_cap(cs, KVM_CAP_PPC_EPR, 0, mpic_proxy);
    if (ret && mpic_proxy) {
        error_report("This KVM version does not support EPR");
        exit(1);
    }
}

int kvmppc_smt_threads(void)
{
    return cap_ppc_smt ? cap_ppc_smt : 1;
}

#ifdef TARGET_PPC64
off_t kvmppc_alloc_rma(void **rma)
{
    off_t size;
    int fd;
    struct kvm_allocate_rma ret;

    /* If cap_ppc_rma == 0, contiguous RMA allocation is not supported
     * if cap_ppc_rma == 1, contiguous RMA allocation is supported, but
     *                      not necessary on this hardware
     * if cap_ppc_rma == 2, contiguous RMA allocation is needed on this hardware
     *
     * FIXME: We should allow the user to force contiguous RMA
     * allocation in the cap_ppc_rma==1 case.
     */
    if (cap_ppc_rma < 2) {
        return 0;
    }

    fd = kvm_vm_ioctl(kvm_state, KVM_ALLOCATE_RMA, &ret);
    if (fd < 0) {
        fprintf(stderr, "KVM: Error on KVM_ALLOCATE_RMA: %s\n",
                strerror(errno));
        return -1;
    }

    size = MIN(ret.rma_size, 256ul << 20);

    *rma = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (*rma == MAP_FAILED) {
        fprintf(stderr, "KVM: Error mapping RMA: %s\n", strerror(errno));
        return -1;
    };

    return size;
}

uint64_t kvmppc_rma_size(uint64_t current_size, unsigned int hash_shift)
{
    struct kvm_ppc_smmu_info info;
    long rampagesize, best_page_shift;
    int i;

    if (cap_ppc_rma >= 2) {
        return current_size;
    }

    /* Find the largest hardware supported page size that's less than
     * or equal to the (logical) backing page size of guest RAM */
    kvm_get_smmu_info(POWERPC_CPU(first_cpu), &info);
    rampagesize = qemu_getrampagesize();
    best_page_shift = 0;

    for (i = 0; i < KVM_PPC_PAGE_SIZES_MAX_SZ; i++) {
        struct kvm_ppc_one_seg_page_size *sps = &info.sps[i];

        if (!sps->page_shift) {
            continue;
        }

        if ((sps->page_shift > best_page_shift)
            && ((1UL << sps->page_shift) <= rampagesize)) {
            best_page_shift = sps->page_shift;
        }
    }

    return MIN(current_size,
               1ULL << (best_page_shift + hash_shift - 7));
}
#endif

bool kvmppc_spapr_use_multitce(void)
{
    return cap_spapr_multitce;
}

void *kvmppc_create_spapr_tce(uint32_t liobn, uint32_t window_size, int *pfd,
                              bool need_vfio)
{
    struct kvm_create_spapr_tce args = {
        .liobn = liobn,
        .window_size = window_size,
    };
    long len;
    int fd;
    void *table;

    /* Must set fd to -1 so we don't try to munmap when called for
     * destroying the table, which the upper layers -will- do
     */
    *pfd = -1;
    if (!cap_spapr_tce || (need_vfio && !cap_spapr_vfio)) {
        return NULL;
    }

    fd = kvm_vm_ioctl(kvm_state, KVM_CREATE_SPAPR_TCE, &args);
    if (fd < 0) {
        fprintf(stderr, "KVM: Failed to create TCE table for liobn 0x%x\n",
                liobn);
        return NULL;
    }

    len = (window_size / SPAPR_TCE_PAGE_SIZE) * sizeof(uint64_t);
    /* FIXME: round this up to page size */

    table = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (table == MAP_FAILED) {
        fprintf(stderr, "KVM: Failed to map TCE table for liobn 0x%x\n",
                liobn);
        close(fd);
        return NULL;
    }

    *pfd = fd;
    return table;
}

int kvmppc_remove_spapr_tce(void *table, int fd, uint32_t nb_table)
{
    long len;

    if (fd < 0) {
        return -1;
    }

    len = nb_table * sizeof(uint64_t);
    if ((munmap(table, len) < 0) ||
        (close(fd) < 0)) {
        fprintf(stderr, "KVM: Unexpected error removing TCE table: %s",
                strerror(errno));
        /* Leak the table */
    }

    return 0;
}

int kvmppc_reset_htab(int shift_hint)
{
    uint32_t shift = shift_hint;

    if (!kvm_enabled()) {
        /* Full emulation, tell caller to allocate htab itself */
        return 0;
    }
    if (kvm_check_extension(kvm_state, KVM_CAP_PPC_ALLOC_HTAB)) {
        int ret;
        ret = kvm_vm_ioctl(kvm_state, KVM_PPC_ALLOCATE_HTAB, &shift);
        if (ret == -ENOTTY) {
            /* At least some versions of PR KVM advertise the
             * capability, but don't implement the ioctl().  Oops.
             * Return 0 so that we allocate the htab in qemu, as is
             * correct for PR. */
            return 0;
        } else if (ret < 0) {
            return ret;
        }
        return shift;
    }

    /* We have a kernel that predates the htab reset calls.  For PR
     * KVM, we need to allocate the htab ourselves, for an HV KVM of
     * this era, it has allocated a 16MB fixed size hash table already. */
    if (kvmppc_is_pr(kvm_state)) {
        /* PR - tell caller to allocate htab */
        return 0;
    } else {
        /* HV - assume 16MB kernel allocated htab */
        return 24;
    }
}

static inline uint32_t mfpvr(void)
{
    uint32_t pvr;

    asm ("mfpvr %0"
         : "=r"(pvr));
    return pvr;
}

static void alter_insns(uint64_t *word, uint64_t flags, bool on)
{
    if (on) {
        *word |= flags;
    } else {
        *word &= ~flags;
    }
}

static void kvmppc_host_cpu_initfn(Object *obj)
{
    assert(kvm_enabled());
}

static void kvmppc_host_cpu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(oc);
    uint32_t vmx = kvmppc_get_vmx();
    uint32_t dfp = kvmppc_get_dfp();
    uint32_t dcache_size = kvmppc_read_int_cpu_dt("d-cache-size");
    uint32_t icache_size = kvmppc_read_int_cpu_dt("i-cache-size");

    /* Now fix up the class with information we can query from the host */
    pcc->pvr = mfpvr();

    if (vmx != -1) {
        /* Only override when we know what the host supports */
        alter_insns(&pcc->insns_flags, PPC_ALTIVEC, vmx > 0);
        alter_insns(&pcc->insns_flags2, PPC2_VSX, vmx > 1);
    }
    if (dfp != -1) {
        /* Only override when we know what the host supports */
        alter_insns(&pcc->insns_flags2, PPC2_DFP, dfp);
    }

    if (dcache_size != -1) {
        pcc->l1_dcache_size = dcache_size;
    }

    if (icache_size != -1) {
        pcc->l1_icache_size = icache_size;
    }

    /* Reason: kvmppc_host_cpu_initfn() dies when !kvm_enabled() */
    dc->cannot_destroy_with_object_finalize_yet = true;
}

bool kvmppc_has_cap_epr(void)
{
    return cap_epr;
}

bool kvmppc_has_cap_htab_fd(void)
{
    return cap_htab_fd;
}

bool kvmppc_has_cap_fixup_hcalls(void)
{
    return cap_fixup_hcalls;
}

bool kvmppc_has_cap_htm(void)
{
    return cap_htm;
}

static PowerPCCPUClass *ppc_cpu_get_family_class(PowerPCCPUClass *pcc)
{
    ObjectClass *oc = OBJECT_CLASS(pcc);

    while (oc && !object_class_is_abstract(oc)) {
        oc = object_class_get_parent(oc);
    }
    assert(oc);

    return POWERPC_CPU_CLASS(oc);
}

PowerPCCPUClass *kvm_ppc_get_host_cpu_class(void)
{
    uint32_t host_pvr = mfpvr();
    PowerPCCPUClass *pvr_pcc;

    pvr_pcc = ppc_cpu_class_by_pvr(host_pvr);
    if (pvr_pcc == NULL) {
        pvr_pcc = ppc_cpu_class_by_pvr_mask(host_pvr);
    }

    return pvr_pcc;
}

static int kvm_ppc_register_host_cpu_type(void)
{
    TypeInfo type_info = {
        .name = TYPE_HOST_POWERPC_CPU,
        .instance_init = kvmppc_host_cpu_initfn,
        .class_init = kvmppc_host_cpu_class_init,
    };
    PowerPCCPUClass *pvr_pcc;
    DeviceClass *dc;
    int i;

    pvr_pcc = kvm_ppc_get_host_cpu_class();
    if (pvr_pcc == NULL) {
        return -1;
    }
    type_info.parent = object_class_get_name(OBJECT_CLASS(pvr_pcc));
    type_register(&type_info);

#if defined(TARGET_PPC64)
    type_info.name = g_strdup_printf("%s-"TYPE_SPAPR_CPU_CORE, "host");
    type_info.parent = TYPE_SPAPR_CPU_CORE,
    type_info.instance_size = sizeof(sPAPRCPUCore);
    type_info.instance_init = NULL;
    type_info.class_init = spapr_cpu_core_class_init;
    type_info.class_data = (void *) "host";
    type_register(&type_info);
    g_free((void *)type_info.name);
#endif

    /*
     * Update generic CPU family class alias (e.g. on a POWER8NVL host,
     * we want "POWER8" to be a "family" alias that points to the current
     * host CPU type, too)
     */
    dc = DEVICE_CLASS(ppc_cpu_get_family_class(pvr_pcc));
    for (i = 0; ppc_cpu_aliases[i].alias != NULL; i++) {
        if (strcmp(ppc_cpu_aliases[i].alias, dc->desc) == 0) {
            ObjectClass *oc = OBJECT_CLASS(pvr_pcc);
            char *suffix;

            ppc_cpu_aliases[i].model = g_strdup(object_class_get_name(oc));
            suffix = strstr(ppc_cpu_aliases[i].model, "-"TYPE_POWERPC_CPU);
            if (suffix) {
                *suffix = 0;
            }
            ppc_cpu_aliases[i].oc = oc;
            break;
        }
    }

    return 0;
}

int kvmppc_define_rtas_kernel_token(uint32_t token, const char *function)
{
    struct kvm_rtas_token_args args = {
        .token = token,
    };

    if (!kvm_check_extension(kvm_state, KVM_CAP_PPC_RTAS)) {
        return -ENOENT;
    }

    strncpy(args.name, function, sizeof(args.name));

    return kvm_vm_ioctl(kvm_state, KVM_PPC_RTAS_DEFINE_TOKEN, &args);
}

int kvmppc_get_htab_fd(bool write)
{
    struct kvm_get_htab_fd s = {
        .flags = write ? KVM_GET_HTAB_WRITE : 0,
        .start_index = 0,
    };

    if (!cap_htab_fd) {
        fprintf(stderr, "KVM version doesn't support saving the hash table\n");
        return -1;
    }

    return kvm_vm_ioctl(kvm_state, KVM_PPC_GET_HTAB_FD, &s);
}

int kvmppc_save_htab(QEMUFile *f, int fd, size_t bufsize, int64_t max_ns)
{
    int64_t starttime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint8_t buf[bufsize];
    ssize_t rc;

    do {
        rc = read(fd, buf, bufsize);
        if (rc < 0) {
            fprintf(stderr, "Error reading data from KVM HTAB fd: %s\n",
                    strerror(errno));
            return rc;
        } else if (rc) {
            uint8_t *buffer = buf;
            ssize_t n = rc;
            while (n) {
                struct kvm_get_htab_header *head =
                    (struct kvm_get_htab_header *) buffer;
                size_t chunksize = sizeof(*head) +
                     HASH_PTE_SIZE_64 * head->n_valid;

                qemu_put_be32(f, head->index);
                qemu_put_be16(f, head->n_valid);
                qemu_put_be16(f, head->n_invalid);
                qemu_put_buffer(f, (void *)(head + 1),
                                HASH_PTE_SIZE_64 * head->n_valid);

                buffer += chunksize;
                n -= chunksize;
            }
        }
    } while ((rc != 0)
             && ((max_ns < 0)
                 || ((qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - starttime) < max_ns)));

    return (rc == 0) ? 1 : 0;
}

int kvmppc_load_htab_chunk(QEMUFile *f, int fd, uint32_t index,
                           uint16_t n_valid, uint16_t n_invalid)
{
    struct kvm_get_htab_header *buf;
    size_t chunksize = sizeof(*buf) + n_valid*HASH_PTE_SIZE_64;
    ssize_t rc;

    buf = alloca(chunksize);
    buf->index = index;
    buf->n_valid = n_valid;
    buf->n_invalid = n_invalid;

    qemu_get_buffer(f, (void *)(buf + 1), HASH_PTE_SIZE_64*n_valid);

    rc = write(fd, buf, chunksize);
    if (rc < 0) {
        fprintf(stderr, "Error writing KVM hash table: %s\n",
                strerror(errno));
        return rc;
    }
    if (rc != chunksize) {
        /* We should never get a short write on a single chunk */
        fprintf(stderr, "Short write, restoring KVM hash table\n");
        return -1;
    }
    return 0;
}

bool kvm_arch_stop_on_emulation_error(CPUState *cpu)
{
    return true;
}

void kvm_arch_init_irq_routing(KVMState *s)
{
}

void kvmppc_read_hptes(ppc_hash_pte64_t *hptes, hwaddr ptex, int n)
{
    struct kvm_get_htab_fd ghf = {
        .flags = 0,
        .start_index = ptex,
    };
    int fd, rc;
    int i;

    fd = kvm_vm_ioctl(kvm_state, KVM_PPC_GET_HTAB_FD, &ghf);
    if (fd < 0) {
        hw_error("kvmppc_read_hptes: Unable to open HPT fd");
    }

    i = 0;
    while (i < n) {
        struct kvm_get_htab_header *hdr;
        int m = n < HPTES_PER_GROUP ? n : HPTES_PER_GROUP;
        char buf[sizeof(*hdr) + m * HASH_PTE_SIZE_64];

        rc = read(fd, buf, sizeof(buf));
        if (rc < 0) {
            hw_error("kvmppc_read_hptes: Unable to read HPTEs");
        }

        hdr = (struct kvm_get_htab_header *)buf;
        while ((i < n) && ((char *)hdr < (buf + rc))) {
            int invalid = hdr->n_invalid;

            if (hdr->index != (ptex + i)) {
                hw_error("kvmppc_read_hptes: Unexpected HPTE index %"PRIu32
                         " != (%"HWADDR_PRIu" + %d", hdr->index, ptex, i);
            }

            memcpy(hptes + i, hdr + 1, HASH_PTE_SIZE_64 * hdr->n_valid);
            i += hdr->n_valid;

            if ((n - i) < invalid) {
                invalid = n - i;
            }
            memset(hptes + i, 0, invalid * HASH_PTE_SIZE_64);
            i += hdr->n_invalid;

            hdr = (struct kvm_get_htab_header *)
                ((char *)(hdr + 1) + HASH_PTE_SIZE_64 * hdr->n_valid);
        }
    }

    close(fd);
}

void kvmppc_write_hpte(hwaddr ptex, uint64_t pte0, uint64_t pte1)
{
    int fd, rc;
    struct kvm_get_htab_fd ghf;
    struct {
        struct kvm_get_htab_header hdr;
        uint64_t pte0;
        uint64_t pte1;
    } buf;

    ghf.flags = 0;
    ghf.start_index = 0;     /* Ignored */
    fd = kvm_vm_ioctl(kvm_state, KVM_PPC_GET_HTAB_FD, &ghf);
    if (fd < 0) {
        hw_error("kvmppc_write_hpte: Unable to open HPT fd");
    }

    buf.hdr.n_valid = 1;
    buf.hdr.n_invalid = 0;
    buf.hdr.index = ptex;
    buf.pte0 = cpu_to_be64(pte0);
    buf.pte1 = cpu_to_be64(pte1);

    rc = write(fd, &buf, sizeof(buf));
    if (rc != sizeof(buf)) {
        hw_error("kvmppc_write_hpte: Unable to update KVM HPT");
    }
    close(fd);
}

int kvm_arch_fixup_msi_route(struct kvm_irq_routing_entry *route,
                             uint64_t address, uint32_t data, PCIDevice *dev)
{
    return 0;
}

int kvm_arch_add_msi_route_post(struct kvm_irq_routing_entry *route,
                                int vector, PCIDevice *dev)
{
    return 0;
}

int kvm_arch_release_virq_post(int virq)
{
    return 0;
}

int kvm_arch_msi_data_to_gsi(uint32_t data)
{
    return data & 0xffff;
}

int kvmppc_enable_hwrng(void)
{
    if (!kvm_enabled() || !kvm_check_extension(kvm_state, KVM_CAP_PPC_HWRNG)) {
        return -1;
    }

    return kvmppc_enable_hcall(kvm_state, H_RANDOM);
}

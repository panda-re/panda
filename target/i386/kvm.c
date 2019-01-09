/*
 * QEMU KVM support
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include <linux/kvm.h>
#include <linux/kvm_para.h>

#include "qemu-common.h"
#include "cpu.h"
#include "sysemu/sysemu.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm_int.h"
#include "kvm_i386.h"
#include "hyperv.h"

#include "exec/gdbstub.h"
#include "qemu/host-utils.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "hw/i386/pc.h"
#include "hw/i386/apic.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/apic-msidef.h"
#include "hw/i386/intel_iommu.h"
#include "hw/i386/x86-iommu.h"

#include "exec/ioport.h"
#include "standard-headers/asm-x86/hyperv.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "migration/migration.h"
#include "exec/memattrs.h"
#include "trace.h"

//#define DEBUG_KVM

#ifdef DEBUG_KVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MSR_KVM_WALL_CLOCK  0x11
#define MSR_KVM_SYSTEM_TIME 0x12

/* A 4096-byte buffer can hold the 8-byte kvm_msrs header, plus
 * 255 kvm_msr_entry structs */
#define MSR_BUF_SIZE 4096

const KVMCapabilityInfo kvm_arch_required_capabilities[] = {
    KVM_CAP_INFO(SET_TSS_ADDR),
    KVM_CAP_INFO(EXT_CPUID),
    KVM_CAP_INFO(MP_STATE),
    KVM_CAP_LAST_INFO
};

static bool has_msr_star;
static bool has_msr_hsave_pa;
static bool has_msr_tsc_aux;
static bool has_msr_tsc_adjust;
static bool has_msr_tsc_deadline;
static bool has_msr_feature_control;
static bool has_msr_misc_enable;
static bool has_msr_smbase;
static bool has_msr_bndcfgs;
static int lm_capable_kernel;
static bool has_msr_hv_hypercall;
static bool has_msr_hv_crash;
static bool has_msr_hv_reset;
static bool has_msr_hv_vpindex;
static bool has_msr_hv_runtime;
static bool has_msr_hv_synic;
static bool has_msr_hv_stimer;
static bool has_msr_xss;

static bool has_msr_architectural_pmu;
static uint32_t num_architectural_pmu_counters;

static int has_xsave;
static int has_xcrs;
static int has_pit_state2;

static bool has_msr_mcg_ext_ctl;

static struct kvm_cpuid2 *cpuid_cache;

int kvm_has_pit_state2(void)
{
    return has_pit_state2;
}

bool kvm_has_smm(void)
{
    return kvm_check_extension(kvm_state, KVM_CAP_X86_SMM);
}

bool kvm_has_adjust_clock_stable(void)
{
    int ret = kvm_check_extension(kvm_state, KVM_CAP_ADJUST_CLOCK);

    return (ret == KVM_CLOCK_TSC_STABLE);
}

bool kvm_allows_irq0_override(void)
{
    return !kvm_irqchip_in_kernel() || kvm_has_gsi_routing();
}

static bool kvm_x2apic_api_set_flags(uint64_t flags)
{
    KVMState *s = KVM_STATE(current_machine->accelerator);

    return !kvm_vm_enable_cap(s, KVM_CAP_X2APIC_API, 0, flags);
}

#define MEMORIZE(fn, _result) \
    ({ \
        static bool _memorized; \
        \
        if (_memorized) { \
            return _result; \
        } \
        _memorized = true; \
        _result = fn; \
    })

static bool has_x2apic_api;

bool kvm_has_x2apic_api(void)
{
    return has_x2apic_api;
}

bool kvm_enable_x2apic(void)
{
    return MEMORIZE(
             kvm_x2apic_api_set_flags(KVM_X2APIC_API_USE_32BIT_IDS |
                                      KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK),
             has_x2apic_api);
}

static int kvm_get_tsc(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[1];
    } msr_data;
    int ret;

    if (env->tsc_valid) {
        return 0;
    }

    msr_data.info.nmsrs = 1;
    msr_data.entries[0].index = MSR_IA32_TSC;
    env->tsc_valid = !runstate_is_running();

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_MSRS, &msr_data);
    if (ret < 0) {
        return ret;
    }

    assert(ret == 1);
    env->tsc = msr_data.entries[0].data;
    return 0;
}

static inline void do_kvm_synchronize_tsc(CPUState *cpu, run_on_cpu_data arg)
{
    kvm_get_tsc(cpu);
}

void kvm_synchronize_all_tsc(void)
{
    CPUState *cpu;

    if (kvm_enabled()) {
        CPU_FOREACH(cpu) {
            run_on_cpu(cpu, do_kvm_synchronize_tsc, RUN_ON_CPU_NULL);
        }
    }
}

static struct kvm_cpuid2 *try_get_cpuid(KVMState *s, int max)
{
    struct kvm_cpuid2 *cpuid;
    int r, size;

    size = sizeof(*cpuid) + max * sizeof(*cpuid->entries);
    cpuid = g_malloc0(size);
    cpuid->nent = max;
    r = kvm_ioctl(s, KVM_GET_SUPPORTED_CPUID, cpuid);
    if (r == 0 && cpuid->nent >= max) {
        r = -E2BIG;
    }
    if (r < 0) {
        if (r == -E2BIG) {
            g_free(cpuid);
            return NULL;
        } else {
            fprintf(stderr, "KVM_GET_SUPPORTED_CPUID failed: %s\n",
                    strerror(-r));
            exit(1);
        }
    }
    return cpuid;
}

/* Run KVM_GET_SUPPORTED_CPUID ioctl(), allocating a buffer large enough
 * for all entries.
 */
static struct kvm_cpuid2 *get_supported_cpuid(KVMState *s)
{
    struct kvm_cpuid2 *cpuid;
    int max = 1;

    if (cpuid_cache != NULL) {
        return cpuid_cache;
    }
    while ((cpuid = try_get_cpuid(s, max)) == NULL) {
        max *= 2;
    }
    cpuid_cache = cpuid;
    return cpuid;
}

static const struct kvm_para_features {
    int cap;
    int feature;
} para_features[] = {
    { KVM_CAP_CLOCKSOURCE, KVM_FEATURE_CLOCKSOURCE },
    { KVM_CAP_NOP_IO_DELAY, KVM_FEATURE_NOP_IO_DELAY },
    { KVM_CAP_PV_MMU, KVM_FEATURE_MMU_OP },
    { KVM_CAP_ASYNC_PF, KVM_FEATURE_ASYNC_PF },
};

static int get_para_features(KVMState *s)
{
    int i, features = 0;

    for (i = 0; i < ARRAY_SIZE(para_features); i++) {
        if (kvm_check_extension(s, para_features[i].cap)) {
            features |= (1 << para_features[i].feature);
        }
    }

    return features;
}

static bool host_tsx_blacklisted(void)
{
    int family, model, stepping;\
    char vendor[CPUID_VENDOR_SZ + 1];

    host_vendor_fms(vendor, &family, &model, &stepping);

    /* Check if we are running on a Haswell host known to have broken TSX */
    return !strcmp(vendor, CPUID_VENDOR_INTEL) &&
           (family == 6) &&
           ((model == 63 && stepping < 4) ||
            model == 60 || model == 69 || model == 70);
}

/* Returns the value for a specific register on the cpuid entry
 */
static uint32_t cpuid_entry_get_reg(struct kvm_cpuid_entry2 *entry, int reg)
{
    uint32_t ret = 0;
    switch (reg) {
    case R_EAX:
        ret = entry->eax;
        break;
    case R_EBX:
        ret = entry->ebx;
        break;
    case R_ECX:
        ret = entry->ecx;
        break;
    case R_EDX:
        ret = entry->edx;
        break;
    }
    return ret;
}

/* Find matching entry for function/index on kvm_cpuid2 struct
 */
static struct kvm_cpuid_entry2 *cpuid_find_entry(struct kvm_cpuid2 *cpuid,
                                                 uint32_t function,
                                                 uint32_t index)
{
    int i;
    for (i = 0; i < cpuid->nent; ++i) {
        if (cpuid->entries[i].function == function &&
            cpuid->entries[i].index == index) {
            return &cpuid->entries[i];
        }
    }
    /* not found: */
    return NULL;
}

uint32_t kvm_arch_get_supported_cpuid(KVMState *s, uint32_t function,
                                      uint32_t index, int reg)
{
    struct kvm_cpuid2 *cpuid;
    uint32_t ret = 0;
    uint32_t cpuid_1_edx;
    bool found = false;

    cpuid = get_supported_cpuid(s);

    struct kvm_cpuid_entry2 *entry = cpuid_find_entry(cpuid, function, index);
    if (entry) {
        found = true;
        ret = cpuid_entry_get_reg(entry, reg);
    }

    /* Fixups for the data returned by KVM, below */

    if (function == 1 && reg == R_EDX) {
        /* KVM before 2.6.30 misreports the following features */
        ret |= CPUID_MTRR | CPUID_PAT | CPUID_MCE | CPUID_MCA;
    } else if (function == 1 && reg == R_ECX) {
        /* We can set the hypervisor flag, even if KVM does not return it on
         * GET_SUPPORTED_CPUID
         */
        ret |= CPUID_EXT_HYPERVISOR;
        /* tsc-deadline flag is not returned by GET_SUPPORTED_CPUID, but it
         * can be enabled if the kernel has KVM_CAP_TSC_DEADLINE_TIMER,
         * and the irqchip is in the kernel.
         */
        if (kvm_irqchip_in_kernel() &&
                kvm_check_extension(s, KVM_CAP_TSC_DEADLINE_TIMER)) {
            ret |= CPUID_EXT_TSC_DEADLINE_TIMER;
        }

        /* x2apic is reported by GET_SUPPORTED_CPUID, but it can't be enabled
         * without the in-kernel irqchip
         */
        if (!kvm_irqchip_in_kernel()) {
            ret &= ~CPUID_EXT_X2APIC;
        }
    } else if (function == 6 && reg == R_EAX) {
        ret |= CPUID_6_EAX_ARAT; /* safe to allow because of emulated APIC */
    } else if (function == 7 && index == 0 && reg == R_EBX) {
        if (host_tsx_blacklisted()) {
            ret &= ~(CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_HLE);
        }
    } else if (function == 0x80000001 && reg == R_EDX) {
        /* On Intel, kvm returns cpuid according to the Intel spec,
         * so add missing bits according to the AMD spec:
         */
        cpuid_1_edx = kvm_arch_get_supported_cpuid(s, 1, 0, R_EDX);
        ret |= cpuid_1_edx & CPUID_EXT2_AMD_ALIASES;
    } else if (function == KVM_CPUID_FEATURES && reg == R_EAX) {
        /* kvm_pv_unhalt is reported by GET_SUPPORTED_CPUID, but it can't
         * be enabled without the in-kernel irqchip
         */
        if (!kvm_irqchip_in_kernel()) {
            ret &= ~(1U << KVM_FEATURE_PV_UNHALT);
        }
    }

    /* fallback for older kernels */
    if ((function == KVM_CPUID_FEATURES) && !found) {
        ret = get_para_features(s);
    }

    return ret;
}

typedef struct HWPoisonPage {
    ram_addr_t ram_addr;
    QLIST_ENTRY(HWPoisonPage) list;
} HWPoisonPage;

static QLIST_HEAD(, HWPoisonPage) hwpoison_page_list =
    QLIST_HEAD_INITIALIZER(hwpoison_page_list);

static void kvm_unpoison_all(void *param)
{
    HWPoisonPage *page, *next_page;

    QLIST_FOREACH_SAFE(page, &hwpoison_page_list, list, next_page) {
        QLIST_REMOVE(page, list);
        qemu_ram_remap(page->ram_addr, TARGET_PAGE_SIZE);
        g_free(page);
    }
}

static void kvm_hwpoison_page_add(ram_addr_t ram_addr)
{
    HWPoisonPage *page;

    QLIST_FOREACH(page, &hwpoison_page_list, list) {
        if (page->ram_addr == ram_addr) {
            return;
        }
    }
    page = g_new(HWPoisonPage, 1);
    page->ram_addr = ram_addr;
    QLIST_INSERT_HEAD(&hwpoison_page_list, page, list);
}

static int kvm_get_mce_cap_supported(KVMState *s, uint64_t *mce_cap,
                                     int *max_banks)
{
    int r;

    r = kvm_check_extension(s, KVM_CAP_MCE);
    if (r > 0) {
        *max_banks = r;
        return kvm_ioctl(s, KVM_X86_GET_MCE_CAP_SUPPORTED, mce_cap);
    }
    return -ENOSYS;
}

static void kvm_mce_inject(X86CPU *cpu, hwaddr paddr, int code)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    uint64_t status = MCI_STATUS_VAL | MCI_STATUS_UC | MCI_STATUS_EN |
                      MCI_STATUS_MISCV | MCI_STATUS_ADDRV | MCI_STATUS_S;
    uint64_t mcg_status = MCG_STATUS_MCIP;
    int flags = 0;

    if (code == BUS_MCEERR_AR) {
        status |= MCI_STATUS_AR | 0x134;
        mcg_status |= MCG_STATUS_EIPV;
    } else {
        status |= 0xc0;
        mcg_status |= MCG_STATUS_RIPV;
    }

    flags = cpu_x86_support_mca_broadcast(env) ? MCE_INJECT_BROADCAST : 0;
    /* We need to read back the value of MSR_EXT_MCG_CTL that was set by the
     * guest kernel back into env->mcg_ext_ctl.
     */
    cpu_synchronize_state(cs);
    if (env->mcg_ext_ctl & MCG_EXT_CTL_LMCE_EN) {
        mcg_status |= MCG_STATUS_LMCE;
        flags = 0;
    }

    cpu_x86_inject_mce(NULL, cpu, 9, status, mcg_status, paddr,
                       (MCM_ADDR_PHYS << 6) | 0xc, flags);
}

static void hardware_memory_error(void)
{
    fprintf(stderr, "Hardware memory error!\n");
    exit(1);
}

void kvm_arch_on_sigbus_vcpu(CPUState *c, int code, void *addr)
{
    X86CPU *cpu = X86_CPU(c);
    CPUX86State *env = &cpu->env;
    ram_addr_t ram_addr;
    hwaddr paddr;

    /* If we get an action required MCE, it has been injected by KVM
     * while the VM was running.  An action optional MCE instead should
     * be coming from the main thread, which qemu_init_sigbus identifies
     * as the "early kill" thread.
     */
    assert(code == BUS_MCEERR_AR || code == BUS_MCEERR_AO);

    if ((env->mcg_cap & MCG_SER_P) && addr) {
        ram_addr = qemu_ram_addr_from_host(addr);
        if (ram_addr != RAM_ADDR_INVALID &&
            kvm_physical_memory_addr_from_host(c->kvm_state, addr, &paddr)) {
            kvm_hwpoison_page_add(ram_addr);
            kvm_mce_inject(cpu, paddr, code);
            return;
        }

        fprintf(stderr, "Hardware memory error for memory used by "
                "QEMU itself instead of guest system!\n");
    }

    if (code == BUS_MCEERR_AR) {
        hardware_memory_error();
    }

    /* Hope we are lucky for AO MCE */
}

static int kvm_inject_mce_oldstyle(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;

    if (!kvm_has_vcpu_events() && env->exception_injected == EXCP12_MCHK) {
        unsigned int bank, bank_num = env->mcg_cap & 0xff;
        struct kvm_x86_mce mce;

        env->exception_injected = -1;

        /*
         * There must be at least one bank in use if an MCE is pending.
         * Find it and use its values for the event injection.
         */
        for (bank = 0; bank < bank_num; bank++) {
            if (env->mce_banks[bank * 4 + 1] & MCI_STATUS_VAL) {
                break;
            }
        }
        assert(bank < bank_num);

        mce.bank = bank;
        mce.status = env->mce_banks[bank * 4 + 1];
        mce.mcg_status = env->mcg_status;
        mce.addr = env->mce_banks[bank * 4 + 2];
        mce.misc = env->mce_banks[bank * 4 + 3];

        return kvm_vcpu_ioctl(CPU(cpu), KVM_X86_SET_MCE, &mce);
    }
    return 0;
}

static void cpu_update_state(void *opaque, int running, RunState state)
{
    CPUX86State *env = opaque;

    if (running) {
        env->tsc_valid = false;
    }
}

unsigned long kvm_arch_vcpu_id(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    return cpu->apic_id;
}

#ifndef KVM_CPUID_SIGNATURE_NEXT
#define KVM_CPUID_SIGNATURE_NEXT                0x40000100
#endif

static bool hyperv_hypercall_available(X86CPU *cpu)
{
    return cpu->hyperv_vapic ||
           (cpu->hyperv_spinlock_attempts != HYPERV_SPINLOCK_NEVER_RETRY);
}

static bool hyperv_enabled(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    return kvm_check_extension(cs->kvm_state, KVM_CAP_HYPERV) > 0 &&
           (hyperv_hypercall_available(cpu) ||
            cpu->hyperv_time  ||
            cpu->hyperv_relaxed_timing ||
            cpu->hyperv_crash ||
            cpu->hyperv_reset ||
            cpu->hyperv_vpindex ||
            cpu->hyperv_runtime ||
            cpu->hyperv_synic ||
            cpu->hyperv_stimer);
}

static int kvm_arch_set_tsc_khz(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int r;

    if (!env->tsc_khz) {
        return 0;
    }

    r = kvm_check_extension(cs->kvm_state, KVM_CAP_TSC_CONTROL) ?
        kvm_vcpu_ioctl(cs, KVM_SET_TSC_KHZ, env->tsc_khz) :
        -ENOTSUP;
    if (r < 0) {
        /* When KVM_SET_TSC_KHZ fails, it's an error only if the current
         * TSC frequency doesn't match the one we want.
         */
        int cur_freq = kvm_check_extension(cs->kvm_state, KVM_CAP_GET_TSC_KHZ) ?
                       kvm_vcpu_ioctl(cs, KVM_GET_TSC_KHZ) :
                       -ENOTSUP;
        if (cur_freq <= 0 || cur_freq != env->tsc_khz) {
            error_report("warning: TSC frequency mismatch between "
                         "VM (%" PRId64 " kHz) and host (%d kHz), "
                         "and TSC scaling unavailable",
                         env->tsc_khz, cur_freq);
            return r;
        }
    }

    return 0;
}

static int hyperv_handle_properties(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (cpu->hyperv_time &&
            kvm_check_extension(cs->kvm_state, KVM_CAP_HYPERV_TIME) <= 0) {
        cpu->hyperv_time = false;
    }

    if (cpu->hyperv_relaxed_timing) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_HYPERCALL_AVAILABLE;
    }
    if (cpu->hyperv_vapic) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_HYPERCALL_AVAILABLE;
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_APIC_ACCESS_AVAILABLE;
    }
    if (cpu->hyperv_time) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_HYPERCALL_AVAILABLE;
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_TIME_REF_COUNT_AVAILABLE;
        env->features[FEAT_HYPERV_EAX] |= 0x200;
    }
    if (cpu->hyperv_crash && has_msr_hv_crash) {
        env->features[FEAT_HYPERV_EDX] |= HV_X64_GUEST_CRASH_MSR_AVAILABLE;
    }
    env->features[FEAT_HYPERV_EDX] |= HV_X64_CPU_DYNAMIC_PARTITIONING_AVAILABLE;
    if (cpu->hyperv_reset && has_msr_hv_reset) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_RESET_AVAILABLE;
    }
    if (cpu->hyperv_vpindex && has_msr_hv_vpindex) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_VP_INDEX_AVAILABLE;
    }
    if (cpu->hyperv_runtime && has_msr_hv_runtime) {
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_VP_RUNTIME_AVAILABLE;
    }
    if (cpu->hyperv_synic) {
        int sint;

        if (!has_msr_hv_synic ||
            kvm_vcpu_enable_cap(cs, KVM_CAP_HYPERV_SYNIC, 0)) {
            fprintf(stderr, "Hyper-V SynIC is not supported by kernel\n");
            return -ENOSYS;
        }

        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_SYNIC_AVAILABLE;
        env->msr_hv_synic_version = HV_SYNIC_VERSION_1;
        for (sint = 0; sint < ARRAY_SIZE(env->msr_hv_synic_sint); sint++) {
            env->msr_hv_synic_sint[sint] = HV_SYNIC_SINT_MASKED;
        }
    }
    if (cpu->hyperv_stimer) {
        if (!has_msr_hv_stimer) {
            fprintf(stderr, "Hyper-V timers aren't supported by kernel\n");
            return -ENOSYS;
        }
        env->features[FEAT_HYPERV_EAX] |= HV_X64_MSR_SYNTIMER_AVAILABLE;
    }
    return 0;
}

static Error *invtsc_mig_blocker;

#define KVM_MAX_CPUID_ENTRIES  100

int kvm_arch_init_vcpu(CPUState *cs)
{
    struct {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[KVM_MAX_CPUID_ENTRIES];
    } QEMU_PACKED cpuid_data;
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    uint32_t limit, i, j, cpuid_i;
    uint32_t unused;
    struct kvm_cpuid_entry2 *c;
    uint32_t signature[3];
    int kvm_base = KVM_CPUID_SIGNATURE;
    int r;
    Error *local_err = NULL;

    memset(&cpuid_data, 0, sizeof(cpuid_data));

    cpuid_i = 0;

    /* Paravirtualization CPUIDs */
    if (hyperv_enabled(cpu)) {
        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS;
        if (!cpu->hyperv_vendor_id) {
            memcpy(signature, "Microsoft Hv", 12);
        } else {
            size_t len = strlen(cpu->hyperv_vendor_id);

            if (len > 12) {
                error_report("hv-vendor-id truncated to 12 characters");
                len = 12;
            }
            memset(signature, 0, 12);
            memcpy(signature, cpu->hyperv_vendor_id, len);
        }
        c->eax = HYPERV_CPUID_MIN;
        c->ebx = signature[0];
        c->ecx = signature[1];
        c->edx = signature[2];

        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_INTERFACE;
        memcpy(signature, "Hv#1\0\0\0\0\0\0\0\0", 12);
        c->eax = signature[0];
        c->ebx = 0;
        c->ecx = 0;
        c->edx = 0;

        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_VERSION;
        c->eax = 0x00001bbc;
        c->ebx = 0x00060001;

        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_FEATURES;
        r = hyperv_handle_properties(cs);
        if (r) {
            return r;
        }
        c->eax = env->features[FEAT_HYPERV_EAX];
        c->ebx = env->features[FEAT_HYPERV_EBX];
        c->edx = env->features[FEAT_HYPERV_EDX];

        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_ENLIGHTMENT_INFO;
        if (cpu->hyperv_relaxed_timing) {
            c->eax |= HV_X64_RELAXED_TIMING_RECOMMENDED;
        }
        if (cpu->hyperv_vapic) {
            c->eax |= HV_X64_APIC_ACCESS_RECOMMENDED;
        }
        c->ebx = cpu->hyperv_spinlock_attempts;

        c = &cpuid_data.entries[cpuid_i++];
        c->function = HYPERV_CPUID_IMPLEMENT_LIMITS;
        c->eax = 0x40;
        c->ebx = 0x40;

        kvm_base = KVM_CPUID_SIGNATURE_NEXT;
        has_msr_hv_hypercall = true;
    }

    if (cpu->expose_kvm) {
        memcpy(signature, "KVMKVMKVM\0\0\0", 12);
        c = &cpuid_data.entries[cpuid_i++];
        c->function = KVM_CPUID_SIGNATURE | kvm_base;
        c->eax = KVM_CPUID_FEATURES | kvm_base;
        c->ebx = signature[0];
        c->ecx = signature[1];
        c->edx = signature[2];

        c = &cpuid_data.entries[cpuid_i++];
        c->function = KVM_CPUID_FEATURES | kvm_base;
        c->eax = env->features[FEAT_KVM];
    }

    cpu_x86_cpuid(env, 0, 0, &limit, &unused, &unused, &unused);

    for (i = 0; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            fprintf(stderr, "unsupported level value: 0x%x\n", limit);
            abort();
        }
        c = &cpuid_data.entries[cpuid_i++];

        switch (i) {
        case 2: {
            /* Keep reading function 2 till all the input is received */
            int times;

            c->function = i;
            c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC |
                       KVM_CPUID_FLAG_STATE_READ_NEXT;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax & 0xff;

            for (j = 1; j < times; ++j) {
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                            "cpuid(eax:2):eax & 0xf = 0x%x\n", times);
                    abort();
                }
                c = &cpuid_data.entries[cpuid_i++];
                c->function = i;
                c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC;
                cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        case 4:
        case 0xb:
        case 0xd:
            for (j = 0; ; j++) {
                if (i == 0xd && j == 64) {
                    break;
                }
                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (i == 4 && c->eax == 0) {
                    break;
                }
                if (i == 0xb && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0xd && c->eax == 0) {
                    continue;
                }
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                            "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    abort();
                }
                c = &cpuid_data.entries[cpuid_i++];
            }
            break;
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            break;
        }
    }

    if (limit >= 0x0a) {
        uint32_t ver;

        cpu_x86_cpuid(env, 0x0a, 0, &ver, &unused, &unused, &unused);
        if ((ver & 0xff) > 0) {
            has_msr_architectural_pmu = true;
            num_architectural_pmu_counters = (ver & 0xff00) >> 8;

            /* Shouldn't be more than 32, since that's the number of bits
             * available in EBX to tell us _which_ counters are available.
             * Play it safe.
             */
            if (num_architectural_pmu_counters > MAX_GP_COUNTERS) {
                num_architectural_pmu_counters = MAX_GP_COUNTERS;
            }
        }
    }

    cpu_x86_cpuid(env, 0x80000000, 0, &limit, &unused, &unused, &unused);

    for (i = 0x80000000; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            fprintf(stderr, "unsupported xlevel value: 0x%x\n", limit);
            abort();
        }
        c = &cpuid_data.entries[cpuid_i++];

        c->function = i;
        c->flags = 0;
        cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
    }

    /* Call Centaur's CPUID instructions they are supported. */
    if (env->cpuid_xlevel2 > 0) {
        cpu_x86_cpuid(env, 0xC0000000, 0, &limit, &unused, &unused, &unused);

        for (i = 0xC0000000; i <= limit; i++) {
            if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                fprintf(stderr, "unsupported xlevel2 value: 0x%x\n", limit);
                abort();
            }
            c = &cpuid_data.entries[cpuid_i++];

            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
        }
    }

    cpuid_data.cpuid.nent = cpuid_i;

    if (((env->cpuid_version >> 8)&0xF) >= 6
        && (env->features[FEAT_1_EDX] & (CPUID_MCE | CPUID_MCA)) ==
           (CPUID_MCE | CPUID_MCA)
        && kvm_check_extension(cs->kvm_state, KVM_CAP_MCE) > 0) {
        uint64_t mcg_cap, unsupported_caps;
        int banks;
        int ret;

        ret = kvm_get_mce_cap_supported(cs->kvm_state, &mcg_cap, &banks);
        if (ret < 0) {
            fprintf(stderr, "kvm_get_mce_cap_supported: %s", strerror(-ret));
            return ret;
        }

        if (banks < (env->mcg_cap & MCG_CAP_BANKS_MASK)) {
            error_report("kvm: Unsupported MCE bank count (QEMU = %d, KVM = %d)",
                         (int)(env->mcg_cap & MCG_CAP_BANKS_MASK), banks);
            return -ENOTSUP;
        }

        unsupported_caps = env->mcg_cap & ~(mcg_cap | MCG_CAP_BANKS_MASK);
        if (unsupported_caps) {
            if (unsupported_caps & MCG_LMCE_P) {
                error_report("kvm: LMCE not supported");
                return -ENOTSUP;
            }
            error_report("warning: Unsupported MCG_CAP bits: 0x%" PRIx64,
                         unsupported_caps);
        }

        env->mcg_cap &= mcg_cap | MCG_CAP_BANKS_MASK;
        ret = kvm_vcpu_ioctl(cs, KVM_X86_SETUP_MCE, &env->mcg_cap);
        if (ret < 0) {
            fprintf(stderr, "KVM_X86_SETUP_MCE: %s", strerror(-ret));
            return ret;
        }
    }

    qemu_add_vm_change_state_handler(cpu_update_state, env);

    c = cpuid_find_entry(&cpuid_data.cpuid, 1, 0);
    if (c) {
        has_msr_feature_control = !!(c->ecx & CPUID_EXT_VMX) ||
                                  !!(c->ecx & CPUID_EXT_SMX);
    }

    if (env->mcg_cap & MCG_LMCE_P) {
        has_msr_mcg_ext_ctl = has_msr_feature_control = true;
    }

    if (!env->user_tsc_khz) {
        if ((env->features[FEAT_8000_0007_EDX] & CPUID_APM_INVTSC) &&
            invtsc_mig_blocker == NULL) {
            /* for migration */
            error_setg(&invtsc_mig_blocker,
                       "State blocked by non-migratable CPU device"
                       " (invtsc flag)");
            r = migrate_add_blocker(invtsc_mig_blocker, &local_err);
            if (local_err) {
                error_report_err(local_err);
                error_free(invtsc_mig_blocker);
                goto fail;
            }
            /* for savevm */
            vmstate_x86_cpu.unmigratable = 1;
        }
    }

    r = kvm_arch_set_tsc_khz(cs);
    if (r < 0) {
        goto fail;
    }

    /* vcpu's TSC frequency is either specified by user, or following
     * the value used by KVM if the former is not present. In the
     * latter case, we query it from KVM and record in env->tsc_khz,
     * so that vcpu's TSC frequency can be migrated later via this field.
     */
    if (!env->tsc_khz) {
        r = kvm_check_extension(cs->kvm_state, KVM_CAP_GET_TSC_KHZ) ?
            kvm_vcpu_ioctl(cs, KVM_GET_TSC_KHZ) :
            -ENOTSUP;
        if (r > 0) {
            env->tsc_khz = r;
        }
    }

    if (cpu->vmware_cpuid_freq
        /* Guests depend on 0x40000000 to detect this feature, so only expose
         * it if KVM exposes leaf 0x40000000. (Conflicts with Hyper-V) */
        && cpu->expose_kvm
        && kvm_base == KVM_CPUID_SIGNATURE
        /* TSC clock must be stable and known for this feature. */
        && ((env->features[FEAT_8000_0007_EDX] & CPUID_APM_INVTSC)
            || env->user_tsc_khz != 0)
        && env->tsc_khz != 0) {

        c = &cpuid_data.entries[cpuid_i++];
        c->function = KVM_CPUID_SIGNATURE | 0x10;
        c->eax = env->tsc_khz;
        /* LAPIC resolution of 1ns (freq: 1GHz) is hardcoded in KVM's
         * APIC_BUS_CYCLE_NS */
        c->ebx = 1000000;
        c->ecx = c->edx = 0;

        c = cpuid_find_entry(&cpuid_data.cpuid, kvm_base, 0);
        c->eax = MAX(c->eax, KVM_CPUID_SIGNATURE | 0x10);
    }

    cpuid_data.cpuid.nent = cpuid_i;

    cpuid_data.cpuid.padding = 0;
    r = kvm_vcpu_ioctl(cs, KVM_SET_CPUID2, &cpuid_data);
    if (r) {
        goto fail;
    }

    if (has_xsave) {
        env->kvm_xsave_buf = qemu_memalign(4096, sizeof(struct kvm_xsave));
    }
    cpu->kvm_msr_buf = g_malloc0(MSR_BUF_SIZE);

    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_RDTSCP)) {
        has_msr_tsc_aux = false;
    }

    return 0;

 fail:
    migrate_del_blocker(invtsc_mig_blocker);
    return r;
}

void kvm_arch_reset_vcpu(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;

    env->exception_injected = -1;
    env->interrupt_injected = -1;
    env->xcr0 = 1;
    if (kvm_irqchip_in_kernel()) {
        env->mp_state = cpu_is_bsp(cpu) ? KVM_MP_STATE_RUNNABLE :
                                          KVM_MP_STATE_UNINITIALIZED;
    } else {
        env->mp_state = KVM_MP_STATE_RUNNABLE;
    }
}

void kvm_arch_do_init_vcpu(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;

    /* APs get directly into wait-for-SIPI state.  */
    if (env->mp_state == KVM_MP_STATE_UNINITIALIZED) {
        env->mp_state = KVM_MP_STATE_INIT_RECEIVED;
    }
}

static int kvm_get_supported_msrs(KVMState *s)
{
    static int kvm_supported_msrs;
    int ret = 0;

    /* first time */
    if (kvm_supported_msrs == 0) {
        struct kvm_msr_list msr_list, *kvm_msr_list;

        kvm_supported_msrs = -1;

        /* Obtain MSR list from KVM.  These are the MSRs that we must
         * save/restore */
        msr_list.nmsrs = 0;
        ret = kvm_ioctl(s, KVM_GET_MSR_INDEX_LIST, &msr_list);
        if (ret < 0 && ret != -E2BIG) {
            return ret;
        }
        /* Old kernel modules had a bug and could write beyond the provided
           memory. Allocate at least a safe amount of 1K. */
        kvm_msr_list = g_malloc0(MAX(1024, sizeof(msr_list) +
                                              msr_list.nmsrs *
                                              sizeof(msr_list.indices[0])));

        kvm_msr_list->nmsrs = msr_list.nmsrs;
        ret = kvm_ioctl(s, KVM_GET_MSR_INDEX_LIST, kvm_msr_list);
        if (ret >= 0) {
            int i;

            for (i = 0; i < kvm_msr_list->nmsrs; i++) {
                if (kvm_msr_list->indices[i] == MSR_STAR) {
                    has_msr_star = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_VM_HSAVE_PA) {
                    has_msr_hsave_pa = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_TSC_AUX) {
                    has_msr_tsc_aux = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_TSC_ADJUST) {
                    has_msr_tsc_adjust = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_TSCDEADLINE) {
                    has_msr_tsc_deadline = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_SMBASE) {
                    has_msr_smbase = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_MISC_ENABLE) {
                    has_msr_misc_enable = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_BNDCFGS) {
                    has_msr_bndcfgs = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == MSR_IA32_XSS) {
                    has_msr_xss = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_CRASH_CTL) {
                    has_msr_hv_crash = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_RESET) {
                    has_msr_hv_reset = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_VP_INDEX) {
                    has_msr_hv_vpindex = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_VP_RUNTIME) {
                    has_msr_hv_runtime = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_SCONTROL) {
                    has_msr_hv_synic = true;
                    continue;
                }
                if (kvm_msr_list->indices[i] == HV_X64_MSR_STIMER0_CONFIG) {
                    has_msr_hv_stimer = true;
                    continue;
                }
            }
        }

        g_free(kvm_msr_list);
    }

    return ret;
}

static Notifier smram_machine_done;
static KVMMemoryListener smram_listener;
static AddressSpace smram_address_space;
static MemoryRegion smram_as_root;
static MemoryRegion smram_as_mem;

static void register_smram_listener(Notifier *n, void *unused)
{
    MemoryRegion *smram =
        (MemoryRegion *) object_resolve_path("/machine/smram", NULL);

    /* Outer container... */
    memory_region_init(&smram_as_root, OBJECT(kvm_state), "mem-container-smram", ~0ull);
    memory_region_set_enabled(&smram_as_root, true);

    /* ... with two regions inside: normal system memory with low
     * priority, and...
     */
    memory_region_init_alias(&smram_as_mem, OBJECT(kvm_state), "mem-smram",
                             get_system_memory(), 0, ~0ull);
    memory_region_add_subregion_overlap(&smram_as_root, 0, &smram_as_mem, 0);
    memory_region_set_enabled(&smram_as_mem, true);

    if (smram) {
        /* ... SMRAM with higher priority */
        memory_region_add_subregion_overlap(&smram_as_root, 0, smram, 10);
        memory_region_set_enabled(smram, true);
    }

    address_space_init(&smram_address_space, &smram_as_root, "KVM-SMRAM");
    kvm_memory_listener_register(kvm_state, &smram_listener,
                                 &smram_address_space, 1);
}

int kvm_arch_init(MachineState *ms, KVMState *s)
{
    uint64_t identity_base = 0xfffbc000;
    uint64_t shadow_mem;
    int ret;
    struct utsname utsname;

#ifdef KVM_CAP_XSAVE
    has_xsave = kvm_check_extension(s, KVM_CAP_XSAVE);
#endif

#ifdef KVM_CAP_XCRS
    has_xcrs = kvm_check_extension(s, KVM_CAP_XCRS);
#endif

#ifdef KVM_CAP_PIT_STATE2
    has_pit_state2 = kvm_check_extension(s, KVM_CAP_PIT_STATE2);
#endif

    ret = kvm_get_supported_msrs(s);
    if (ret < 0) {
        return ret;
    }

    uname(&utsname);
    lm_capable_kernel = strcmp(utsname.machine, "x86_64") == 0;

    /*
     * On older Intel CPUs, KVM uses vm86 mode to emulate 16-bit code directly.
     * In order to use vm86 mode, an EPT identity map and a TSS  are needed.
     * Since these must be part of guest physical memory, we need to allocate
     * them, both by setting their start addresses in the kernel and by
     * creating a corresponding e820 entry. We need 4 pages before the BIOS.
     *
     * Older KVM versions may not support setting the identity map base. In
     * that case we need to stick with the default, i.e. a 256K maximum BIOS
     * size.
     */
    if (kvm_check_extension(s, KVM_CAP_SET_IDENTITY_MAP_ADDR)) {
        /* Allows up to 16M BIOSes. */
        identity_base = 0xfeffc000;

        ret = kvm_vm_ioctl(s, KVM_SET_IDENTITY_MAP_ADDR, &identity_base);
        if (ret < 0) {
            return ret;
        }
    }

    /* Set TSS base one page after EPT identity map. */
    ret = kvm_vm_ioctl(s, KVM_SET_TSS_ADDR, identity_base + 0x1000);
    if (ret < 0) {
        return ret;
    }

    /* Tell fw_cfg to notify the BIOS to reserve the range. */
    ret = e820_add_entry(identity_base, 0x4000, E820_RESERVED);
    if (ret < 0) {
        fprintf(stderr, "e820_add_entry() table is full\n");
        return ret;
    }
    qemu_register_reset(kvm_unpoison_all, NULL);

    shadow_mem = machine_kvm_shadow_mem(ms);
    if (shadow_mem != -1) {
        shadow_mem /= 4096;
        ret = kvm_vm_ioctl(s, KVM_SET_NR_MMU_PAGES, shadow_mem);
        if (ret < 0) {
            return ret;
        }
    }

    if (kvm_check_extension(s, KVM_CAP_X86_SMM)) {
        smram_machine_done.notify = register_smram_listener;
        qemu_add_machine_init_done_notifier(&smram_machine_done);
    }
    return 0;
}

static void set_v8086_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = 3;
    lhs->present = 1;
    lhs->dpl = 3;
    lhs->db = 0;
    lhs->s = 1;
    lhs->l = 0;
    lhs->g = 0;
    lhs->avl = 0;
    lhs->unusable = 0;
}

static void set_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = !lhs->present;
    lhs->padding = 0;
}

static void get_seg(SegmentCache *lhs, const struct kvm_segment *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    if (rhs->unusable) {
        lhs->flags = 0;
    } else {
        lhs->flags = (rhs->type << DESC_TYPE_SHIFT) |
                     (rhs->present * DESC_P_MASK) |
                     (rhs->dpl << DESC_DPL_SHIFT) |
                     (rhs->db << DESC_B_SHIFT) |
                     (rhs->s * DESC_S_MASK) |
                     (rhs->l << DESC_L_SHIFT) |
                     (rhs->g * DESC_G_MASK) |
                     (rhs->avl * DESC_AVL_MASK);
    }
}

static void kvm_getput_reg(__u64 *kvm_reg, target_ulong *qemu_reg, int set)
{
    if (set) {
        *kvm_reg = *qemu_reg;
    } else {
        *qemu_reg = *kvm_reg;
    }
}

static int kvm_getput_regs(X86CPU *cpu, int set)
{
    CPUX86State *env = &cpu->env;
    struct kvm_regs regs;
    int ret = 0;

    if (!set) {
        ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_REGS, &regs);
        if (ret < 0) {
            return ret;
        }
    }

    kvm_getput_reg(&regs.rax, &env->regs[R_EAX], set);
    kvm_getput_reg(&regs.rbx, &env->regs[R_EBX], set);
    kvm_getput_reg(&regs.rcx, &env->regs[R_ECX], set);
    kvm_getput_reg(&regs.rdx, &env->regs[R_EDX], set);
    kvm_getput_reg(&regs.rsi, &env->regs[R_ESI], set);
    kvm_getput_reg(&regs.rdi, &env->regs[R_EDI], set);
    kvm_getput_reg(&regs.rsp, &env->regs[R_ESP], set);
    kvm_getput_reg(&regs.rbp, &env->regs[R_EBP], set);
#ifdef TARGET_X86_64
    kvm_getput_reg(&regs.r8, &env->regs[8], set);
    kvm_getput_reg(&regs.r9, &env->regs[9], set);
    kvm_getput_reg(&regs.r10, &env->regs[10], set);
    kvm_getput_reg(&regs.r11, &env->regs[11], set);
    kvm_getput_reg(&regs.r12, &env->regs[12], set);
    kvm_getput_reg(&regs.r13, &env->regs[13], set);
    kvm_getput_reg(&regs.r14, &env->regs[14], set);
    kvm_getput_reg(&regs.r15, &env->regs[15], set);
#endif

    kvm_getput_reg(&regs.rflags, &env->eflags, set);
    kvm_getput_reg(&regs.rip, &env->eip, set);

    if (set) {
        ret = kvm_vcpu_ioctl(CPU(cpu), KVM_SET_REGS, &regs);
    }

    return ret;
}

static int kvm_put_fpu(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_fpu fpu;
    int i;

    memset(&fpu, 0, sizeof fpu);
    fpu.fsw = env->fpus & ~(7 << 11);
    fpu.fsw |= (env->fpstt & 7) << 11;
    fpu.fcw = env->fpuc;
    fpu.last_opcode = env->fpop;
    fpu.last_ip = env->fpip;
    fpu.last_dp = env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu.ftwx |= (!env->fptags[i]) << i;
    }
    memcpy(fpu.fpr, env->fpregs, sizeof env->fpregs);
    for (i = 0; i < CPU_NB_REGS; i++) {
        stq_p(&fpu.xmm[i][0], env->xmm_regs[i].ZMM_Q(0));
        stq_p(&fpu.xmm[i][8], env->xmm_regs[i].ZMM_Q(1));
    }
    fpu.mxcsr = env->mxcsr;

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_FPU, &fpu);
}

#define XSAVE_FCW_FSW     0
#define XSAVE_FTW_FOP     1
#define XSAVE_CWD_RIP     2
#define XSAVE_CWD_RDP     4
#define XSAVE_MXCSR       6
#define XSAVE_ST_SPACE    8
#define XSAVE_XMM_SPACE   40
#define XSAVE_XSTATE_BV   128
#define XSAVE_YMMH_SPACE  144
#define XSAVE_BNDREGS     240
#define XSAVE_BNDCSR      256
#define XSAVE_OPMASK      272
#define XSAVE_ZMM_Hi256   288
#define XSAVE_Hi16_ZMM    416
#define XSAVE_PKRU        672

#define XSAVE_BYTE_OFFSET(word_offset) \
    ((word_offset) * sizeof(((struct kvm_xsave *)0)->region[0]))

#define ASSERT_OFFSET(word_offset, field) \
    QEMU_BUILD_BUG_ON(XSAVE_BYTE_OFFSET(word_offset) != \
                      offsetof(X86XSaveArea, field))

ASSERT_OFFSET(XSAVE_FCW_FSW, legacy.fcw);
ASSERT_OFFSET(XSAVE_FTW_FOP, legacy.ftw);
ASSERT_OFFSET(XSAVE_CWD_RIP, legacy.fpip);
ASSERT_OFFSET(XSAVE_CWD_RDP, legacy.fpdp);
ASSERT_OFFSET(XSAVE_MXCSR, legacy.mxcsr);
ASSERT_OFFSET(XSAVE_ST_SPACE, legacy.fpregs);
ASSERT_OFFSET(XSAVE_XMM_SPACE, legacy.xmm_regs);
ASSERT_OFFSET(XSAVE_XSTATE_BV, header.xstate_bv);
ASSERT_OFFSET(XSAVE_YMMH_SPACE, avx_state);
ASSERT_OFFSET(XSAVE_BNDREGS, bndreg_state);
ASSERT_OFFSET(XSAVE_BNDCSR, bndcsr_state);
ASSERT_OFFSET(XSAVE_OPMASK, opmask_state);
ASSERT_OFFSET(XSAVE_ZMM_Hi256, zmm_hi256_state);
ASSERT_OFFSET(XSAVE_Hi16_ZMM, hi16_zmm_state);
ASSERT_OFFSET(XSAVE_PKRU, pkru_state);

static int kvm_put_xsave(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    X86XSaveArea *xsave = env->kvm_xsave_buf;
    uint16_t cwd, swd, twd;
    int i;

    if (!has_xsave) {
        return kvm_put_fpu(cpu);
    }

    memset(xsave, 0, sizeof(struct kvm_xsave));
    twd = 0;
    swd = env->fpus & ~(7 << 11);
    swd |= (env->fpstt & 7) << 11;
    cwd = env->fpuc;
    for (i = 0; i < 8; ++i) {
        twd |= (!env->fptags[i]) << i;
    }
    xsave->legacy.fcw = cwd;
    xsave->legacy.fsw = swd;
    xsave->legacy.ftw = twd;
    xsave->legacy.fpop = env->fpop;
    xsave->legacy.fpip = env->fpip;
    xsave->legacy.fpdp = env->fpdp;
    memcpy(&xsave->legacy.fpregs, env->fpregs,
            sizeof env->fpregs);
    xsave->legacy.mxcsr = env->mxcsr;
    xsave->header.xstate_bv = env->xstate_bv;
    memcpy(&xsave->bndreg_state.bnd_regs, env->bnd_regs,
            sizeof env->bnd_regs);
    xsave->bndcsr_state.bndcsr = env->bndcs_regs;
    memcpy(&xsave->opmask_state.opmask_regs, env->opmask_regs,
            sizeof env->opmask_regs);

    for (i = 0; i < CPU_NB_REGS; i++) {
        uint8_t *xmm = xsave->legacy.xmm_regs[i];
        uint8_t *ymmh = xsave->avx_state.ymmh[i];
        uint8_t *zmmh = xsave->zmm_hi256_state.zmm_hi256[i];
        stq_p(xmm,     env->xmm_regs[i].ZMM_Q(0));
        stq_p(xmm+8,   env->xmm_regs[i].ZMM_Q(1));
        stq_p(ymmh,    env->xmm_regs[i].ZMM_Q(2));
        stq_p(ymmh+8,  env->xmm_regs[i].ZMM_Q(3));
        stq_p(zmmh,    env->xmm_regs[i].ZMM_Q(4));
        stq_p(zmmh+8,  env->xmm_regs[i].ZMM_Q(5));
        stq_p(zmmh+16, env->xmm_regs[i].ZMM_Q(6));
        stq_p(zmmh+24, env->xmm_regs[i].ZMM_Q(7));
    }

#ifdef TARGET_X86_64
    memcpy(&xsave->hi16_zmm_state.hi16_zmm, &env->xmm_regs[16],
            16 * sizeof env->xmm_regs[16]);
    memcpy(&xsave->pkru_state, &env->pkru, sizeof env->pkru);
#endif
    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_XSAVE, xsave);
}

static int kvm_put_xcrs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_xcrs xcrs = {};

    if (!has_xcrs) {
        return 0;
    }

    xcrs.nr_xcrs = 1;
    xcrs.flags = 0;
    xcrs.xcrs[0].xcr = 0;
    xcrs.xcrs[0].value = env->xcr0;
    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_XCRS, &xcrs);
}

static int kvm_put_sregs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_sregs sregs;

    memset(sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));
    if (env->interrupt_injected >= 0) {
        sregs.interrupt_bitmap[env->interrupt_injected / 64] |=
                (uint64_t)1 << (env->interrupt_injected % 64);
    }

    if ((env->eflags & VM_MASK)) {
        set_v8086_seg(&sregs.cs, &env->segs[R_CS]);
        set_v8086_seg(&sregs.ds, &env->segs[R_DS]);
        set_v8086_seg(&sregs.es, &env->segs[R_ES]);
        set_v8086_seg(&sregs.fs, &env->segs[R_FS]);
        set_v8086_seg(&sregs.gs, &env->segs[R_GS]);
        set_v8086_seg(&sregs.ss, &env->segs[R_SS]);
    } else {
        set_seg(&sregs.cs, &env->segs[R_CS]);
        set_seg(&sregs.ds, &env->segs[R_DS]);
        set_seg(&sregs.es, &env->segs[R_ES]);
        set_seg(&sregs.fs, &env->segs[R_FS]);
        set_seg(&sregs.gs, &env->segs[R_GS]);
        set_seg(&sregs.ss, &env->segs[R_SS]);
    }

    set_seg(&sregs.tr, &env->tr);
    set_seg(&sregs.ldt, &env->ldt);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    memset(sregs.idt.padding, 0, sizeof sregs.idt.padding);
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;
    memset(sregs.gdt.padding, 0, sizeof sregs.gdt.padding);

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];

    sregs.cr8 = cpu_get_apic_tpr(cpu->apic_state);
    sregs.apic_base = cpu_get_apic_base(cpu->apic_state);

    sregs.efer = env->efer;

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_SREGS, &sregs);
}

static void kvm_msr_buf_reset(X86CPU *cpu)
{
    memset(cpu->kvm_msr_buf, 0, MSR_BUF_SIZE);
}

static void kvm_msr_entry_add(X86CPU *cpu, uint32_t index, uint64_t value)
{
    struct kvm_msrs *msrs = cpu->kvm_msr_buf;
    void *limit = ((void *)msrs) + MSR_BUF_SIZE;
    struct kvm_msr_entry *entry = &msrs->entries[msrs->nmsrs];

    assert((void *)(entry + 1) <= limit);

    entry->index = index;
    entry->reserved = 0;
    entry->data = value;
    msrs->nmsrs++;
}

static int kvm_put_one_msr(X86CPU *cpu, int index, uint64_t value)
{
    kvm_msr_buf_reset(cpu);
    kvm_msr_entry_add(cpu, index, value);

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_MSRS, cpu->kvm_msr_buf);
}

void kvm_put_apicbase(X86CPU *cpu, uint64_t value)
{
    int ret;

    ret = kvm_put_one_msr(cpu, MSR_IA32_APICBASE, value);
    assert(ret == 1);
}

static int kvm_put_tscdeadline_msr(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    int ret;

    if (!has_msr_tsc_deadline) {
        return 0;
    }

    ret = kvm_put_one_msr(cpu, MSR_IA32_TSCDEADLINE, env->tsc_deadline);
    if (ret < 0) {
        return ret;
    }

    assert(ret == 1);
    return 0;
}

/*
 * Provide a separate write service for the feature control MSR in order to
 * kick the VCPU out of VMXON or even guest mode on reset. This has to be done
 * before writing any other state because forcibly leaving nested mode
 * invalidates the VCPU state.
 */
static int kvm_put_msr_feature_control(X86CPU *cpu)
{
    int ret;

    if (!has_msr_feature_control) {
        return 0;
    }

    ret = kvm_put_one_msr(cpu, MSR_IA32_FEATURE_CONTROL,
                          cpu->env.msr_ia32_feature_control);
    if (ret < 0) {
        return ret;
    }

    assert(ret == 1);
    return 0;
}

static int kvm_put_msrs(X86CPU *cpu, int level)
{
    CPUX86State *env = &cpu->env;
    int i;
    int ret;

    kvm_msr_buf_reset(cpu);

    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_CS, env->sysenter_cs);
    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    kvm_msr_entry_add(cpu, MSR_PAT, env->pat);
    if (has_msr_star) {
        kvm_msr_entry_add(cpu, MSR_STAR, env->star);
    }
    if (has_msr_hsave_pa) {
        kvm_msr_entry_add(cpu, MSR_VM_HSAVE_PA, env->vm_hsave);
    }
    if (has_msr_tsc_aux) {
        kvm_msr_entry_add(cpu, MSR_TSC_AUX, env->tsc_aux);
    }
    if (has_msr_tsc_adjust) {
        kvm_msr_entry_add(cpu, MSR_TSC_ADJUST, env->tsc_adjust);
    }
    if (has_msr_misc_enable) {
        kvm_msr_entry_add(cpu, MSR_IA32_MISC_ENABLE,
                          env->msr_ia32_misc_enable);
    }
    if (has_msr_smbase) {
        kvm_msr_entry_add(cpu, MSR_IA32_SMBASE, env->smbase);
    }
    if (has_msr_bndcfgs) {
        kvm_msr_entry_add(cpu, MSR_IA32_BNDCFGS, env->msr_bndcfgs);
    }
    if (has_msr_xss) {
        kvm_msr_entry_add(cpu, MSR_IA32_XSS, env->xss);
    }
#ifdef TARGET_X86_64
    if (lm_capable_kernel) {
        kvm_msr_entry_add(cpu, MSR_CSTAR, env->cstar);
        kvm_msr_entry_add(cpu, MSR_KERNELGSBASE, env->kernelgsbase);
        kvm_msr_entry_add(cpu, MSR_FMASK, env->fmask);
        kvm_msr_entry_add(cpu, MSR_LSTAR, env->lstar);
    }
#endif
    /*
     * The following MSRs have side effects on the guest or are too heavy
     * for normal writeback. Limit them to reset or full state updates.
     */
    if (level >= KVM_PUT_RESET_STATE) {
        kvm_msr_entry_add(cpu, MSR_IA32_TSC, env->tsc);
        kvm_msr_entry_add(cpu, MSR_KVM_SYSTEM_TIME, env->system_time_msr);
        kvm_msr_entry_add(cpu, MSR_KVM_WALL_CLOCK, env->wall_clock_msr);
        if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_ASYNC_PF)) {
            kvm_msr_entry_add(cpu, MSR_KVM_ASYNC_PF_EN, env->async_pf_en_msr);
        }
        if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_PV_EOI)) {
            kvm_msr_entry_add(cpu, MSR_KVM_PV_EOI_EN, env->pv_eoi_en_msr);
        }
        if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_STEAL_TIME)) {
            kvm_msr_entry_add(cpu, MSR_KVM_STEAL_TIME, env->steal_time_msr);
        }
        if (has_msr_architectural_pmu) {
            /* Stop the counter.  */
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_FIXED_CTR_CTRL, 0);
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_CTRL, 0);

            /* Set the counter values.  */
            for (i = 0; i < MAX_FIXED_COUNTERS; i++) {
                kvm_msr_entry_add(cpu, MSR_CORE_PERF_FIXED_CTR0 + i,
                                  env->msr_fixed_counters[i]);
            }
            for (i = 0; i < num_architectural_pmu_counters; i++) {
                kvm_msr_entry_add(cpu, MSR_P6_PERFCTR0 + i,
                                  env->msr_gp_counters[i]);
                kvm_msr_entry_add(cpu, MSR_P6_EVNTSEL0 + i,
                                  env->msr_gp_evtsel[i]);
            }
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_STATUS,
                              env->msr_global_status);
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_OVF_CTRL,
                              env->msr_global_ovf_ctrl);

            /* Now start the PMU.  */
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_FIXED_CTR_CTRL,
                              env->msr_fixed_ctr_ctrl);
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_CTRL,
                              env->msr_global_ctrl);
        }
        if (has_msr_hv_hypercall) {
            kvm_msr_entry_add(cpu, HV_X64_MSR_GUEST_OS_ID,
                              env->msr_hv_guest_os_id);
            kvm_msr_entry_add(cpu, HV_X64_MSR_HYPERCALL,
                              env->msr_hv_hypercall);
        }
        if (cpu->hyperv_vapic) {
            kvm_msr_entry_add(cpu, HV_X64_MSR_APIC_ASSIST_PAGE,
                              env->msr_hv_vapic);
        }
        if (cpu->hyperv_time) {
            kvm_msr_entry_add(cpu, HV_X64_MSR_REFERENCE_TSC, env->msr_hv_tsc);
        }
        if (has_msr_hv_crash) {
            int j;

            for (j = 0; j < HV_X64_MSR_CRASH_PARAMS; j++)
                kvm_msr_entry_add(cpu, HV_X64_MSR_CRASH_P0 + j,
                                  env->msr_hv_crash_params[j]);

            kvm_msr_entry_add(cpu, HV_X64_MSR_CRASH_CTL,
                              HV_X64_MSR_CRASH_CTL_NOTIFY);
        }
        if (has_msr_hv_runtime) {
            kvm_msr_entry_add(cpu, HV_X64_MSR_VP_RUNTIME, env->msr_hv_runtime);
        }
        if (cpu->hyperv_synic) {
            int j;

            kvm_msr_entry_add(cpu, HV_X64_MSR_SCONTROL,
                              env->msr_hv_synic_control);
            kvm_msr_entry_add(cpu, HV_X64_MSR_SVERSION,
                              env->msr_hv_synic_version);
            kvm_msr_entry_add(cpu, HV_X64_MSR_SIEFP,
                              env->msr_hv_synic_evt_page);
            kvm_msr_entry_add(cpu, HV_X64_MSR_SIMP,
                              env->msr_hv_synic_msg_page);

            for (j = 0; j < ARRAY_SIZE(env->msr_hv_synic_sint); j++) {
                kvm_msr_entry_add(cpu, HV_X64_MSR_SINT0 + j,
                                  env->msr_hv_synic_sint[j]);
            }
        }
        if (has_msr_hv_stimer) {
            int j;

            for (j = 0; j < ARRAY_SIZE(env->msr_hv_stimer_config); j++) {
                kvm_msr_entry_add(cpu, HV_X64_MSR_STIMER0_CONFIG + j * 2,
                                env->msr_hv_stimer_config[j]);
            }

            for (j = 0; j < ARRAY_SIZE(env->msr_hv_stimer_count); j++) {
                kvm_msr_entry_add(cpu, HV_X64_MSR_STIMER0_COUNT + j * 2,
                                env->msr_hv_stimer_count[j]);
            }
        }
        if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            uint64_t phys_mask = MAKE_64BIT_MASK(0, cpu->phys_bits);

            kvm_msr_entry_add(cpu, MSR_MTRRdefType, env->mtrr_deftype);
            kvm_msr_entry_add(cpu, MSR_MTRRfix64K_00000, env->mtrr_fixed[0]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix16K_80000, env->mtrr_fixed[1]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix16K_A0000, env->mtrr_fixed[2]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_C0000, env->mtrr_fixed[3]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_C8000, env->mtrr_fixed[4]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_D0000, env->mtrr_fixed[5]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_D8000, env->mtrr_fixed[6]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_E0000, env->mtrr_fixed[7]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_E8000, env->mtrr_fixed[8]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_F0000, env->mtrr_fixed[9]);
            kvm_msr_entry_add(cpu, MSR_MTRRfix4K_F8000, env->mtrr_fixed[10]);
            for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
                /* The CPU GPs if we write to a bit above the physical limit of
                 * the host CPU (and KVM emulates that)
                 */
                uint64_t mask = env->mtrr_var[i].mask;
                mask &= phys_mask;

                kvm_msr_entry_add(cpu, MSR_MTRRphysBase(i),
                                  env->mtrr_var[i].base);
                kvm_msr_entry_add(cpu, MSR_MTRRphysMask(i), mask);
            }
        }

        /* Note: MSR_IA32_FEATURE_CONTROL is written separately, see
         *       kvm_put_msr_feature_control. */
    }
    if (env->mcg_cap) {
        int i;

        kvm_msr_entry_add(cpu, MSR_MCG_STATUS, env->mcg_status);
        kvm_msr_entry_add(cpu, MSR_MCG_CTL, env->mcg_ctl);
        if (has_msr_mcg_ext_ctl) {
            kvm_msr_entry_add(cpu, MSR_MCG_EXT_CTL, env->mcg_ext_ctl);
        }
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
            kvm_msr_entry_add(cpu, MSR_MC0_CTL + i, env->mce_banks[i]);
        }
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_SET_MSRS, cpu->kvm_msr_buf);
    if (ret < 0) {
        return ret;
    }

    if (ret < cpu->kvm_msr_buf->nmsrs) {
        struct kvm_msr_entry *e = &cpu->kvm_msr_buf->entries[ret];
        error_report("error: failed to set MSR 0x%" PRIx32 " to 0x%" PRIx64,
                     (uint32_t)e->index, (uint64_t)e->data);
    }

    assert(ret == cpu->kvm_msr_buf->nmsrs);
    return 0;
}


static int kvm_get_fpu(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_fpu fpu;
    int i, ret;

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_FPU, &fpu);
    if (ret < 0) {
        return ret;
    }

    env->fpstt = (fpu.fsw >> 11) & 7;
    env->fpus = fpu.fsw;
    env->fpuc = fpu.fcw;
    env->fpop = fpu.last_opcode;
    env->fpip = fpu.last_ip;
    env->fpdp = fpu.last_dp;
    for (i = 0; i < 8; ++i) {
        env->fptags[i] = !((fpu.ftwx >> i) & 1);
    }
    memcpy(env->fpregs, fpu.fpr, sizeof env->fpregs);
    for (i = 0; i < CPU_NB_REGS; i++) {
        env->xmm_regs[i].ZMM_Q(0) = ldq_p(&fpu.xmm[i][0]);
        env->xmm_regs[i].ZMM_Q(1) = ldq_p(&fpu.xmm[i][8]);
    }
    env->mxcsr = fpu.mxcsr;

    return 0;
}

static int kvm_get_xsave(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    X86XSaveArea *xsave = env->kvm_xsave_buf;
    int ret, i;
    uint16_t cwd, swd, twd;

    if (!has_xsave) {
        return kvm_get_fpu(cpu);
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_XSAVE, xsave);
    if (ret < 0) {
        return ret;
    }

    cwd = xsave->legacy.fcw;
    swd = xsave->legacy.fsw;
    twd = xsave->legacy.ftw;
    env->fpop = xsave->legacy.fpop;
    env->fpstt = (swd >> 11) & 7;
    env->fpus = swd;
    env->fpuc = cwd;
    for (i = 0; i < 8; ++i) {
        env->fptags[i] = !((twd >> i) & 1);
    }
    env->fpip = xsave->legacy.fpip;
    env->fpdp = xsave->legacy.fpdp;
    env->mxcsr = xsave->legacy.mxcsr;
    memcpy(env->fpregs, &xsave->legacy.fpregs,
            sizeof env->fpregs);
    env->xstate_bv = xsave->header.xstate_bv;
    memcpy(env->bnd_regs, &xsave->bndreg_state.bnd_regs,
            sizeof env->bnd_regs);
    env->bndcs_regs = xsave->bndcsr_state.bndcsr;
    memcpy(env->opmask_regs, &xsave->opmask_state.opmask_regs,
            sizeof env->opmask_regs);

    for (i = 0; i < CPU_NB_REGS; i++) {
        uint8_t *xmm = xsave->legacy.xmm_regs[i];
        uint8_t *ymmh = xsave->avx_state.ymmh[i];
        uint8_t *zmmh = xsave->zmm_hi256_state.zmm_hi256[i];
        env->xmm_regs[i].ZMM_Q(0) = ldq_p(xmm);
        env->xmm_regs[i].ZMM_Q(1) = ldq_p(xmm+8);
        env->xmm_regs[i].ZMM_Q(2) = ldq_p(ymmh);
        env->xmm_regs[i].ZMM_Q(3) = ldq_p(ymmh+8);
        env->xmm_regs[i].ZMM_Q(4) = ldq_p(zmmh);
        env->xmm_regs[i].ZMM_Q(5) = ldq_p(zmmh+8);
        env->xmm_regs[i].ZMM_Q(6) = ldq_p(zmmh+16);
        env->xmm_regs[i].ZMM_Q(7) = ldq_p(zmmh+24);
    }

#ifdef TARGET_X86_64
    memcpy(&env->xmm_regs[16], &xsave->hi16_zmm_state.hi16_zmm,
           16 * sizeof env->xmm_regs[16]);
    memcpy(&env->pkru, &xsave->pkru_state, sizeof env->pkru);
#endif
    return 0;
}

static int kvm_get_xcrs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    int i, ret;
    struct kvm_xcrs xcrs;

    if (!has_xcrs) {
        return 0;
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_XCRS, &xcrs);
    if (ret < 0) {
        return ret;
    }

    for (i = 0; i < xcrs.nr_xcrs; i++) {
        /* Only support xcr0 now */
        if (xcrs.xcrs[i].xcr == 0) {
            env->xcr0 = xcrs.xcrs[i].value;
            break;
        }
    }
    return 0;
}

static int kvm_get_sregs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_sregs sregs;
    uint32_t hflags;
    int bit, i, ret;

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_SREGS, &sregs);
    if (ret < 0) {
        return ret;
    }

    /* There can only be one pending IRQ set in the bitmap at a time, so try
       to find it and save its number instead (-1 for none). */
    env->interrupt_injected = -1;
    for (i = 0; i < ARRAY_SIZE(sregs.interrupt_bitmap); i++) {
        if (sregs.interrupt_bitmap[i]) {
            bit = ctz64(sregs.interrupt_bitmap[i]);
            env->interrupt_injected = i * 64 + bit;
            break;
        }
    }

    get_seg(&env->segs[R_CS], &sregs.cs);
    get_seg(&env->segs[R_DS], &sregs.ds);
    get_seg(&env->segs[R_ES], &sregs.es);
    get_seg(&env->segs[R_FS], &sregs.fs);
    get_seg(&env->segs[R_GS], &sregs.gs);
    get_seg(&env->segs[R_SS], &sregs.ss);

    get_seg(&env->tr, &sregs.tr);
    get_seg(&env->ldt, &sregs.ldt);

    env->idt.limit = sregs.idt.limit;
    env->idt.base = sregs.idt.base;
    env->gdt.limit = sregs.gdt.limit;
    env->gdt.base = sregs.gdt.base;

    env->cr[0] = sregs.cr0;
    env->cr[2] = sregs.cr2;
    env->cr[3] = sregs.cr3;
    env->cr[4] = sregs.cr4;

    env->efer = sregs.efer;

    /* changes to apic base and cr8/tpr are read back via kvm_arch_post_run */

#define HFLAG_COPY_MASK \
    ~( HF_CPL_MASK | HF_PE_MASK | HF_MP_MASK | HF_EM_MASK | \
       HF_TS_MASK | HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK | \
       HF_OSFXSR_MASK | HF_LMA_MASK | HF_CS32_MASK | \
       HF_SS32_MASK | HF_CS64_MASK | HF_ADDSEG_MASK)

    hflags = env->hflags & HFLAG_COPY_MASK;
    hflags |= (env->segs[R_SS].flags >> DESC_DPL_SHIFT) & HF_CPL_MASK;
    hflags |= (env->cr[0] & CR0_PE_MASK) << (HF_PE_SHIFT - CR0_PE_SHIFT);
    hflags |= (env->cr[0] << (HF_MP_SHIFT - CR0_MP_SHIFT)) &
                (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK);
    hflags |= (env->eflags & (HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK));

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        hflags |= HF_OSFXSR_MASK;
    }

    if (env->efer & MSR_EFER_LMA) {
        hflags |= HF_LMA_MASK;
    }

    if ((hflags & HF_LMA_MASK) && (env->segs[R_CS].flags & DESC_L_MASK)) {
        hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
    } else {
        hflags |= (env->segs[R_CS].flags & DESC_B_MASK) >>
                    (DESC_B_SHIFT - HF_CS32_SHIFT);
        hflags |= (env->segs[R_SS].flags & DESC_B_MASK) >>
                    (DESC_B_SHIFT - HF_SS32_SHIFT);
        if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK) ||
            !(hflags & HF_CS32_MASK)) {
            hflags |= HF_ADDSEG_MASK;
        } else {
            hflags |= ((env->segs[R_DS].base | env->segs[R_ES].base |
                        env->segs[R_SS].base) != 0) << HF_ADDSEG_SHIFT;
        }
    }
    env->hflags = hflags;

    return 0;
}

static int kvm_get_msrs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_msr_entry *msrs = cpu->kvm_msr_buf->entries;
    int ret, i;
    uint64_t mtrr_top_bits;

    kvm_msr_buf_reset(cpu);

    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_CS, 0);
    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_ESP, 0);
    kvm_msr_entry_add(cpu, MSR_IA32_SYSENTER_EIP, 0);
    kvm_msr_entry_add(cpu, MSR_PAT, 0);
    if (has_msr_star) {
        kvm_msr_entry_add(cpu, MSR_STAR, 0);
    }
    if (has_msr_hsave_pa) {
        kvm_msr_entry_add(cpu, MSR_VM_HSAVE_PA, 0);
    }
    if (has_msr_tsc_aux) {
        kvm_msr_entry_add(cpu, MSR_TSC_AUX, 0);
    }
    if (has_msr_tsc_adjust) {
        kvm_msr_entry_add(cpu, MSR_TSC_ADJUST, 0);
    }
    if (has_msr_tsc_deadline) {
        kvm_msr_entry_add(cpu, MSR_IA32_TSCDEADLINE, 0);
    }
    if (has_msr_misc_enable) {
        kvm_msr_entry_add(cpu, MSR_IA32_MISC_ENABLE, 0);
    }
    if (has_msr_smbase) {
        kvm_msr_entry_add(cpu, MSR_IA32_SMBASE, 0);
    }
    if (has_msr_feature_control) {
        kvm_msr_entry_add(cpu, MSR_IA32_FEATURE_CONTROL, 0);
    }
    if (has_msr_bndcfgs) {
        kvm_msr_entry_add(cpu, MSR_IA32_BNDCFGS, 0);
    }
    if (has_msr_xss) {
        kvm_msr_entry_add(cpu, MSR_IA32_XSS, 0);
    }


    if (!env->tsc_valid) {
        kvm_msr_entry_add(cpu, MSR_IA32_TSC, 0);
        env->tsc_valid = !runstate_is_running();
    }

#ifdef TARGET_X86_64
    if (lm_capable_kernel) {
        kvm_msr_entry_add(cpu, MSR_CSTAR, 0);
        kvm_msr_entry_add(cpu, MSR_KERNELGSBASE, 0);
        kvm_msr_entry_add(cpu, MSR_FMASK, 0);
        kvm_msr_entry_add(cpu, MSR_LSTAR, 0);
    }
#endif
    kvm_msr_entry_add(cpu, MSR_KVM_SYSTEM_TIME, 0);
    kvm_msr_entry_add(cpu, MSR_KVM_WALL_CLOCK, 0);
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_ASYNC_PF)) {
        kvm_msr_entry_add(cpu, MSR_KVM_ASYNC_PF_EN, 0);
    }
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_PV_EOI)) {
        kvm_msr_entry_add(cpu, MSR_KVM_PV_EOI_EN, 0);
    }
    if (env->features[FEAT_KVM] & (1 << KVM_FEATURE_STEAL_TIME)) {
        kvm_msr_entry_add(cpu, MSR_KVM_STEAL_TIME, 0);
    }
    if (has_msr_architectural_pmu) {
        kvm_msr_entry_add(cpu, MSR_CORE_PERF_FIXED_CTR_CTRL, 0);
        kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_CTRL, 0);
        kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_STATUS, 0);
        kvm_msr_entry_add(cpu, MSR_CORE_PERF_GLOBAL_OVF_CTRL, 0);
        for (i = 0; i < MAX_FIXED_COUNTERS; i++) {
            kvm_msr_entry_add(cpu, MSR_CORE_PERF_FIXED_CTR0 + i, 0);
        }
        for (i = 0; i < num_architectural_pmu_counters; i++) {
            kvm_msr_entry_add(cpu, MSR_P6_PERFCTR0 + i, 0);
            kvm_msr_entry_add(cpu, MSR_P6_EVNTSEL0 + i, 0);
        }
    }

    if (env->mcg_cap) {
        kvm_msr_entry_add(cpu, MSR_MCG_STATUS, 0);
        kvm_msr_entry_add(cpu, MSR_MCG_CTL, 0);
        if (has_msr_mcg_ext_ctl) {
            kvm_msr_entry_add(cpu, MSR_MCG_EXT_CTL, 0);
        }
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
            kvm_msr_entry_add(cpu, MSR_MC0_CTL + i, 0);
        }
    }

    if (has_msr_hv_hypercall) {
        kvm_msr_entry_add(cpu, HV_X64_MSR_HYPERCALL, 0);
        kvm_msr_entry_add(cpu, HV_X64_MSR_GUEST_OS_ID, 0);
    }
    if (cpu->hyperv_vapic) {
        kvm_msr_entry_add(cpu, HV_X64_MSR_APIC_ASSIST_PAGE, 0);
    }
    if (cpu->hyperv_time) {
        kvm_msr_entry_add(cpu, HV_X64_MSR_REFERENCE_TSC, 0);
    }
    if (has_msr_hv_crash) {
        int j;

        for (j = 0; j < HV_X64_MSR_CRASH_PARAMS; j++) {
            kvm_msr_entry_add(cpu, HV_X64_MSR_CRASH_P0 + j, 0);
        }
    }
    if (has_msr_hv_runtime) {
        kvm_msr_entry_add(cpu, HV_X64_MSR_VP_RUNTIME, 0);
    }
    if (cpu->hyperv_synic) {
        uint32_t msr;

        kvm_msr_entry_add(cpu, HV_X64_MSR_SCONTROL, 0);
        kvm_msr_entry_add(cpu, HV_X64_MSR_SVERSION, 0);
        kvm_msr_entry_add(cpu, HV_X64_MSR_SIEFP, 0);
        kvm_msr_entry_add(cpu, HV_X64_MSR_SIMP, 0);
        for (msr = HV_X64_MSR_SINT0; msr <= HV_X64_MSR_SINT15; msr++) {
            kvm_msr_entry_add(cpu, msr, 0);
        }
    }
    if (has_msr_hv_stimer) {
        uint32_t msr;

        for (msr = HV_X64_MSR_STIMER0_CONFIG; msr <= HV_X64_MSR_STIMER3_COUNT;
             msr++) {
            kvm_msr_entry_add(cpu, msr, 0);
        }
    }
    if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
        kvm_msr_entry_add(cpu, MSR_MTRRdefType, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix64K_00000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix16K_80000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix16K_A0000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_C0000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_C8000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_D0000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_D8000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_E0000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_E8000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_F0000, 0);
        kvm_msr_entry_add(cpu, MSR_MTRRfix4K_F8000, 0);
        for (i = 0; i < MSR_MTRRcap_VCNT; i++) {
            kvm_msr_entry_add(cpu, MSR_MTRRphysBase(i), 0);
            kvm_msr_entry_add(cpu, MSR_MTRRphysMask(i), 0);
        }
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_MSRS, cpu->kvm_msr_buf);
    if (ret < 0) {
        return ret;
    }

    if (ret < cpu->kvm_msr_buf->nmsrs) {
        struct kvm_msr_entry *e = &cpu->kvm_msr_buf->entries[ret];
        error_report("error: failed to get MSR 0x%" PRIx32,
                     (uint32_t)e->index);
    }

    assert(ret == cpu->kvm_msr_buf->nmsrs);
    /*
     * MTRR masks: Each mask consists of 5 parts
     * a  10..0: must be zero
     * b  11   : valid bit
     * c n-1.12: actual mask bits
     * d  51..n: reserved must be zero
     * e  63.52: reserved must be zero
     *
     * 'n' is the number of physical bits supported by the CPU and is
     * apparently always <= 52.   We know our 'n' but don't know what
     * the destinations 'n' is; it might be smaller, in which case
     * it masks (c) on loading. It might be larger, in which case
     * we fill 'd' so that d..c is consistent irrespetive of the 'n'
     * we're migrating to.
     */

    if (cpu->fill_mtrr_mask) {
        QEMU_BUILD_BUG_ON(TARGET_PHYS_ADDR_SPACE_BITS > 52);
        assert(cpu->phys_bits <= TARGET_PHYS_ADDR_SPACE_BITS);
        mtrr_top_bits = MAKE_64BIT_MASK(cpu->phys_bits, 52 - cpu->phys_bits);
    } else {
        mtrr_top_bits = 0;
    }

    for (i = 0; i < ret; i++) {
        uint32_t index = msrs[i].index;
        switch (index) {
        case MSR_IA32_SYSENTER_CS:
            env->sysenter_cs = msrs[i].data;
            break;
        case MSR_IA32_SYSENTER_ESP:
            env->sysenter_esp = msrs[i].data;
            break;
        case MSR_IA32_SYSENTER_EIP:
            env->sysenter_eip = msrs[i].data;
            break;
        case MSR_PAT:
            env->pat = msrs[i].data;
            break;
        case MSR_STAR:
            env->star = msrs[i].data;
            break;
#ifdef TARGET_X86_64
        case MSR_CSTAR:
            env->cstar = msrs[i].data;
            break;
        case MSR_KERNELGSBASE:
            env->kernelgsbase = msrs[i].data;
            break;
        case MSR_FMASK:
            env->fmask = msrs[i].data;
            break;
        case MSR_LSTAR:
            env->lstar = msrs[i].data;
            break;
#endif
        case MSR_IA32_TSC:
            env->tsc = msrs[i].data;
            break;
        case MSR_TSC_AUX:
            env->tsc_aux = msrs[i].data;
            break;
        case MSR_TSC_ADJUST:
            env->tsc_adjust = msrs[i].data;
            break;
        case MSR_IA32_TSCDEADLINE:
            env->tsc_deadline = msrs[i].data;
            break;
        case MSR_VM_HSAVE_PA:
            env->vm_hsave = msrs[i].data;
            break;
        case MSR_KVM_SYSTEM_TIME:
            env->system_time_msr = msrs[i].data;
            break;
        case MSR_KVM_WALL_CLOCK:
            env->wall_clock_msr = msrs[i].data;
            break;
        case MSR_MCG_STATUS:
            env->mcg_status = msrs[i].data;
            break;
        case MSR_MCG_CTL:
            env->mcg_ctl = msrs[i].data;
            break;
        case MSR_MCG_EXT_CTL:
            env->mcg_ext_ctl = msrs[i].data;
            break;
        case MSR_IA32_MISC_ENABLE:
            env->msr_ia32_misc_enable = msrs[i].data;
            break;
        case MSR_IA32_SMBASE:
            env->smbase = msrs[i].data;
            break;
        case MSR_IA32_FEATURE_CONTROL:
            env->msr_ia32_feature_control = msrs[i].data;
            break;
        case MSR_IA32_BNDCFGS:
            env->msr_bndcfgs = msrs[i].data;
            break;
        case MSR_IA32_XSS:
            env->xss = msrs[i].data;
            break;
        default:
            if (msrs[i].index >= MSR_MC0_CTL &&
                msrs[i].index < MSR_MC0_CTL + (env->mcg_cap & 0xff) * 4) {
                env->mce_banks[msrs[i].index - MSR_MC0_CTL] = msrs[i].data;
            }
            break;
        case MSR_KVM_ASYNC_PF_EN:
            env->async_pf_en_msr = msrs[i].data;
            break;
        case MSR_KVM_PV_EOI_EN:
            env->pv_eoi_en_msr = msrs[i].data;
            break;
        case MSR_KVM_STEAL_TIME:
            env->steal_time_msr = msrs[i].data;
            break;
        case MSR_CORE_PERF_FIXED_CTR_CTRL:
            env->msr_fixed_ctr_ctrl = msrs[i].data;
            break;
        case MSR_CORE_PERF_GLOBAL_CTRL:
            env->msr_global_ctrl = msrs[i].data;
            break;
        case MSR_CORE_PERF_GLOBAL_STATUS:
            env->msr_global_status = msrs[i].data;
            break;
        case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
            env->msr_global_ovf_ctrl = msrs[i].data;
            break;
        case MSR_CORE_PERF_FIXED_CTR0 ... MSR_CORE_PERF_FIXED_CTR0 + MAX_FIXED_COUNTERS - 1:
            env->msr_fixed_counters[index - MSR_CORE_PERF_FIXED_CTR0] = msrs[i].data;
            break;
        case MSR_P6_PERFCTR0 ... MSR_P6_PERFCTR0 + MAX_GP_COUNTERS - 1:
            env->msr_gp_counters[index - MSR_P6_PERFCTR0] = msrs[i].data;
            break;
        case MSR_P6_EVNTSEL0 ... MSR_P6_EVNTSEL0 + MAX_GP_COUNTERS - 1:
            env->msr_gp_evtsel[index - MSR_P6_EVNTSEL0] = msrs[i].data;
            break;
        case HV_X64_MSR_HYPERCALL:
            env->msr_hv_hypercall = msrs[i].data;
            break;
        case HV_X64_MSR_GUEST_OS_ID:
            env->msr_hv_guest_os_id = msrs[i].data;
            break;
        case HV_X64_MSR_APIC_ASSIST_PAGE:
            env->msr_hv_vapic = msrs[i].data;
            break;
        case HV_X64_MSR_REFERENCE_TSC:
            env->msr_hv_tsc = msrs[i].data;
            break;
        case HV_X64_MSR_CRASH_P0 ... HV_X64_MSR_CRASH_P4:
            env->msr_hv_crash_params[index - HV_X64_MSR_CRASH_P0] = msrs[i].data;
            break;
        case HV_X64_MSR_VP_RUNTIME:
            env->msr_hv_runtime = msrs[i].data;
            break;
        case HV_X64_MSR_SCONTROL:
            env->msr_hv_synic_control = msrs[i].data;
            break;
        case HV_X64_MSR_SVERSION:
            env->msr_hv_synic_version = msrs[i].data;
            break;
        case HV_X64_MSR_SIEFP:
            env->msr_hv_synic_evt_page = msrs[i].data;
            break;
        case HV_X64_MSR_SIMP:
            env->msr_hv_synic_msg_page = msrs[i].data;
            break;
        case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
            env->msr_hv_synic_sint[index - HV_X64_MSR_SINT0] = msrs[i].data;
            break;
        case HV_X64_MSR_STIMER0_CONFIG:
        case HV_X64_MSR_STIMER1_CONFIG:
        case HV_X64_MSR_STIMER2_CONFIG:
        case HV_X64_MSR_STIMER3_CONFIG:
            env->msr_hv_stimer_config[(index - HV_X64_MSR_STIMER0_CONFIG)/2] =
                                msrs[i].data;
            break;
        case HV_X64_MSR_STIMER0_COUNT:
        case HV_X64_MSR_STIMER1_COUNT:
        case HV_X64_MSR_STIMER2_COUNT:
        case HV_X64_MSR_STIMER3_COUNT:
            env->msr_hv_stimer_count[(index - HV_X64_MSR_STIMER0_COUNT)/2] =
                                msrs[i].data;
            break;
        case MSR_MTRRdefType:
            env->mtrr_deftype = msrs[i].data;
            break;
        case MSR_MTRRfix64K_00000:
            env->mtrr_fixed[0] = msrs[i].data;
            break;
        case MSR_MTRRfix16K_80000:
            env->mtrr_fixed[1] = msrs[i].data;
            break;
        case MSR_MTRRfix16K_A0000:
            env->mtrr_fixed[2] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_C0000:
            env->mtrr_fixed[3] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_C8000:
            env->mtrr_fixed[4] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_D0000:
            env->mtrr_fixed[5] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_D8000:
            env->mtrr_fixed[6] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_E0000:
            env->mtrr_fixed[7] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_E8000:
            env->mtrr_fixed[8] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_F0000:
            env->mtrr_fixed[9] = msrs[i].data;
            break;
        case MSR_MTRRfix4K_F8000:
            env->mtrr_fixed[10] = msrs[i].data;
            break;
        case MSR_MTRRphysBase(0) ... MSR_MTRRphysMask(MSR_MTRRcap_VCNT - 1):
            if (index & 1) {
                env->mtrr_var[MSR_MTRRphysIndex(index)].mask = msrs[i].data |
                                                               mtrr_top_bits;
            } else {
                env->mtrr_var[MSR_MTRRphysIndex(index)].base = msrs[i].data;
            }
            break;
        }
    }

    return 0;
}

static int kvm_put_mp_state(X86CPU *cpu)
{
    struct kvm_mp_state mp_state = { .mp_state = cpu->env.mp_state };

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_MP_STATE, &mp_state);
}

static int kvm_get_mp_state(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    struct kvm_mp_state mp_state;
    int ret;

    ret = kvm_vcpu_ioctl(cs, KVM_GET_MP_STATE, &mp_state);
    if (ret < 0) {
        return ret;
    }
    env->mp_state = mp_state.mp_state;
    if (kvm_irqchip_in_kernel()) {
        cs->halted = (mp_state.mp_state == KVM_MP_STATE_HALTED);
    }
    return 0;
}

static int kvm_get_apic(X86CPU *cpu)
{
    DeviceState *apic = cpu->apic_state;
    struct kvm_lapic_state kapic;
    int ret;

    if (apic && kvm_irqchip_in_kernel()) {
        ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_LAPIC, &kapic);
        if (ret < 0) {
            return ret;
        }

        kvm_get_apic_state(apic, &kapic);
    }
    return 0;
}

static int kvm_put_vcpu_events(X86CPU *cpu, int level)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    struct kvm_vcpu_events events = {};

    if (!kvm_has_vcpu_events()) {
        return 0;
    }

    events.exception.injected = (env->exception_injected >= 0);
    events.exception.nr = env->exception_injected;
    events.exception.has_error_code = env->has_error_code;
    events.exception.error_code = env->error_code;
    events.exception.pad = 0;

    events.interrupt.injected = (env->interrupt_injected >= 0);
    events.interrupt.nr = env->interrupt_injected;
    events.interrupt.soft = env->soft_interrupt;

    events.nmi.injected = env->nmi_injected;
    events.nmi.pending = env->nmi_pending;
    events.nmi.masked = !!(env->hflags2 & HF2_NMI_MASK);
    events.nmi.pad = 0;

    events.sipi_vector = env->sipi_vector;
    events.flags = 0;

    if (has_msr_smbase) {
        events.smi.smm = !!(env->hflags & HF_SMM_MASK);
        events.smi.smm_inside_nmi = !!(env->hflags2 & HF2_SMM_INSIDE_NMI_MASK);
        if (kvm_irqchip_in_kernel()) {
            /* As soon as these are moved to the kernel, remove them
             * from cs->interrupt_request.
             */
            events.smi.pending = cs->interrupt_request & CPU_INTERRUPT_SMI;
            events.smi.latched_init = cs->interrupt_request & CPU_INTERRUPT_INIT;
            cs->interrupt_request &= ~(CPU_INTERRUPT_INIT | CPU_INTERRUPT_SMI);
        } else {
            /* Keep these in cs->interrupt_request.  */
            events.smi.pending = 0;
            events.smi.latched_init = 0;
        }
        /* Stop SMI delivery on old machine types to avoid a reboot
         * on an inward migration of an old VM.
         */
        if (!cpu->kvm_no_smi_migration) {
            events.flags |= KVM_VCPUEVENT_VALID_SMM;
        }
    }

    if (level >= KVM_PUT_RESET_STATE) {
        events.flags |=
            KVM_VCPUEVENT_VALID_NMI_PENDING | KVM_VCPUEVENT_VALID_SIPI_VECTOR;
    }

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_VCPU_EVENTS, &events);
}

static int kvm_get_vcpu_events(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_vcpu_events events;
    int ret;

    if (!kvm_has_vcpu_events()) {
        return 0;
    }

    memset(&events, 0, sizeof(events));
    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_VCPU_EVENTS, &events);
    if (ret < 0) {
       return ret;
    }
    env->exception_injected =
       events.exception.injected ? events.exception.nr : -1;
    env->has_error_code = events.exception.has_error_code;
    env->error_code = events.exception.error_code;

    env->interrupt_injected =
        events.interrupt.injected ? events.interrupt.nr : -1;
    env->soft_interrupt = events.interrupt.soft;

    env->nmi_injected = events.nmi.injected;
    env->nmi_pending = events.nmi.pending;
    if (events.nmi.masked) {
        env->hflags2 |= HF2_NMI_MASK;
    } else {
        env->hflags2 &= ~HF2_NMI_MASK;
    }

    if (events.flags & KVM_VCPUEVENT_VALID_SMM) {
        if (events.smi.smm) {
            env->hflags |= HF_SMM_MASK;
        } else {
            env->hflags &= ~HF_SMM_MASK;
        }
        if (events.smi.pending) {
            cpu_interrupt(CPU(cpu), CPU_INTERRUPT_SMI);
        } else {
            cpu_reset_interrupt(CPU(cpu), CPU_INTERRUPT_SMI);
        }
        if (events.smi.smm_inside_nmi) {
            env->hflags2 |= HF2_SMM_INSIDE_NMI_MASK;
        } else {
            env->hflags2 &= ~HF2_SMM_INSIDE_NMI_MASK;
        }
        if (events.smi.latched_init) {
            cpu_interrupt(CPU(cpu), CPU_INTERRUPT_INIT);
        } else {
            cpu_reset_interrupt(CPU(cpu), CPU_INTERRUPT_INIT);
        }
    }

    env->sipi_vector = events.sipi_vector;

    return 0;
}

static int kvm_guest_debug_workarounds(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    int ret = 0;
    unsigned long reinject_trap = 0;

    if (!kvm_has_vcpu_events()) {
        if (env->exception_injected == 1) {
            reinject_trap = KVM_GUESTDBG_INJECT_DB;
        } else if (env->exception_injected == 3) {
            reinject_trap = KVM_GUESTDBG_INJECT_BP;
        }
        env->exception_injected = -1;
    }

    /*
     * Kernels before KVM_CAP_X86_ROBUST_SINGLESTEP overwrote flags.TF
     * injected via SET_GUEST_DEBUG while updating GP regs. Work around this
     * by updating the debug state once again if single-stepping is on.
     * Another reason to call kvm_update_guest_debug here is a pending debug
     * trap raise by the guest. On kernels without SET_VCPU_EVENTS we have to
     * reinject them via SET_GUEST_DEBUG.
     */
    if (reinject_trap ||
        (!kvm_has_robust_singlestep() && cs->singlestep_enabled)) {
        ret = kvm_update_guest_debug(cs, reinject_trap);
    }
    return ret;
}

static int kvm_put_debugregs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_debugregs dbgregs;
    int i;

    if (!kvm_has_debugregs()) {
        return 0;
    }

    for (i = 0; i < 4; i++) {
        dbgregs.db[i] = env->dr[i];
    }
    dbgregs.dr6 = env->dr[6];
    dbgregs.dr7 = env->dr[7];
    dbgregs.flags = 0;

    return kvm_vcpu_ioctl(CPU(cpu), KVM_SET_DEBUGREGS, &dbgregs);
}

static int kvm_get_debugregs(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    struct kvm_debugregs dbgregs;
    int i, ret;

    if (!kvm_has_debugregs()) {
        return 0;
    }

    ret = kvm_vcpu_ioctl(CPU(cpu), KVM_GET_DEBUGREGS, &dbgregs);
    if (ret < 0) {
        return ret;
    }
    for (i = 0; i < 4; i++) {
        env->dr[i] = dbgregs.db[i];
    }
    env->dr[4] = env->dr[6] = dbgregs.dr6;
    env->dr[5] = env->dr[7] = dbgregs.dr7;

    return 0;
}

int kvm_arch_put_registers(CPUState *cpu, int level)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    int ret;

    assert(cpu_is_stopped(cpu) || qemu_cpu_is_self(cpu));

    if (level >= KVM_PUT_RESET_STATE) {
        ret = kvm_put_msr_feature_control(x86_cpu);
        if (ret < 0) {
            return ret;
        }
    }

    if (level == KVM_PUT_FULL_STATE) {
        /* We don't check for kvm_arch_set_tsc_khz() errors here,
         * because TSC frequency mismatch shouldn't abort migration,
         * unless the user explicitly asked for a more strict TSC
         * setting (e.g. using an explicit "tsc-freq" option).
         */
        kvm_arch_set_tsc_khz(cpu);
    }

    ret = kvm_getput_regs(x86_cpu, 1);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_xsave(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_xcrs(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_sregs(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    /* must be before kvm_put_msrs */
    ret = kvm_inject_mce_oldstyle(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_msrs(x86_cpu, level);
    if (ret < 0) {
        return ret;
    }
    if (level >= KVM_PUT_RESET_STATE) {
        ret = kvm_put_mp_state(x86_cpu);
        if (ret < 0) {
            return ret;
        }
    }

    ret = kvm_put_tscdeadline_msr(x86_cpu);
    if (ret < 0) {
        return ret;
    }

    ret = kvm_put_vcpu_events(x86_cpu, level);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_put_debugregs(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    /* must be last */
    ret = kvm_guest_debug_workarounds(x86_cpu);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

int kvm_arch_get_registers(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    int ret;

    assert(cpu_is_stopped(cs) || qemu_cpu_is_self(cs));

    ret = kvm_getput_regs(cpu, 0);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_xsave(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_xcrs(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_sregs(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_msrs(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_mp_state(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_apic(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_vcpu_events(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = kvm_get_debugregs(cpu);
    if (ret < 0) {
        goto out;
    }
    ret = 0;
 out:
    cpu_sync_bndcs_hflags(&cpu->env);
    return ret;
}

void kvm_arch_pre_run(CPUState *cpu, struct kvm_run *run)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;
    int ret;

    /* Inject NMI */
    if (cpu->interrupt_request & (CPU_INTERRUPT_NMI | CPU_INTERRUPT_SMI)) {
        if (cpu->interrupt_request & CPU_INTERRUPT_NMI) {
            qemu_mutex_lock_iothread();
            cpu->interrupt_request &= ~CPU_INTERRUPT_NMI;
            qemu_mutex_unlock_iothread();
            DPRINTF("injected NMI\n");
            ret = kvm_vcpu_ioctl(cpu, KVM_NMI);
            if (ret < 0) {
                fprintf(stderr, "KVM: injection failed, NMI lost (%s)\n",
                        strerror(-ret));
            }
        }
        if (cpu->interrupt_request & CPU_INTERRUPT_SMI) {
            qemu_mutex_lock_iothread();
            cpu->interrupt_request &= ~CPU_INTERRUPT_SMI;
            qemu_mutex_unlock_iothread();
            DPRINTF("injected SMI\n");
            ret = kvm_vcpu_ioctl(cpu, KVM_SMI);
            if (ret < 0) {
                fprintf(stderr, "KVM: injection failed, SMI lost (%s)\n",
                        strerror(-ret));
            }
        }
    }

    if (!kvm_pic_in_kernel()) {
        qemu_mutex_lock_iothread();
    }

    /* Force the VCPU out of its inner loop to process any INIT requests
     * or (for userspace APIC, but it is cheap to combine the checks here)
     * pending TPR access reports.
     */
    if (cpu->interrupt_request & (CPU_INTERRUPT_INIT | CPU_INTERRUPT_TPR)) {
        if ((cpu->interrupt_request & CPU_INTERRUPT_INIT) &&
            !(env->hflags & HF_SMM_MASK)) {
            cpu->exit_request = 1;
        }
        if (cpu->interrupt_request & CPU_INTERRUPT_TPR) {
            cpu->exit_request = 1;
        }
    }

    if (!kvm_pic_in_kernel()) {
        /* Try to inject an interrupt if the guest can accept it */
        if (run->ready_for_interrupt_injection &&
            (cpu->interrupt_request & CPU_INTERRUPT_HARD) &&
            (env->eflags & IF_MASK)) {
            int irq;

            cpu->interrupt_request &= ~CPU_INTERRUPT_HARD;
            irq = cpu_get_pic_interrupt(env);
            if (irq >= 0) {
                struct kvm_interrupt intr;

                intr.irq = irq;
                DPRINTF("injected interrupt %d\n", irq);
                ret = kvm_vcpu_ioctl(cpu, KVM_INTERRUPT, &intr);
                if (ret < 0) {
                    fprintf(stderr,
                            "KVM: injection failed, interrupt lost (%s)\n",
                            strerror(-ret));
                }
            }
        }

        /* If we have an interrupt but the guest is not ready to receive an
         * interrupt, request an interrupt window exit.  This will
         * cause a return to userspace as soon as the guest is ready to
         * receive interrupts. */
        if ((cpu->interrupt_request & CPU_INTERRUPT_HARD)) {
            run->request_interrupt_window = 1;
        } else {
            run->request_interrupt_window = 0;
        }

        DPRINTF("setting tpr\n");
        run->cr8 = cpu_get_apic_tpr(x86_cpu->apic_state);

        qemu_mutex_unlock_iothread();
    }
}

MemTxAttrs kvm_arch_post_run(CPUState *cpu, struct kvm_run *run)
{
    X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;

    if (run->flags & KVM_RUN_X86_SMM) {
        env->hflags |= HF_SMM_MASK;
    } else {
        env->hflags &= ~HF_SMM_MASK;
    }
    if (run->if_flag) {
        env->eflags |= IF_MASK;
    } else {
        env->eflags &= ~IF_MASK;
    }

    /* We need to protect the apic state against concurrent accesses from
     * different threads in case the userspace irqchip is used. */
    if (!kvm_irqchip_in_kernel()) {
        qemu_mutex_lock_iothread();
    }
    cpu_set_apic_tpr(x86_cpu->apic_state, run->cr8);
    cpu_set_apic_base(x86_cpu->apic_state, run->apic_base);
    if (!kvm_irqchip_in_kernel()) {
        qemu_mutex_unlock_iothread();
    }
    return cpu_get_mem_attrs(env);
}

int kvm_arch_process_async_events(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (cs->interrupt_request & CPU_INTERRUPT_MCE) {
        /* We must not raise CPU_INTERRUPT_MCE if it's not supported. */
        assert(env->mcg_cap);

        cs->interrupt_request &= ~CPU_INTERRUPT_MCE;

        kvm_cpu_synchronize_state(cs);

        if (env->exception_injected == EXCP08_DBLE) {
            /* this means triple fault */
            qemu_system_reset_request();
            cs->exit_request = 1;
            return 0;
        }
        env->exception_injected = EXCP12_MCHK;
        env->has_error_code = 0;

        cs->halted = 0;
        if (kvm_irqchip_in_kernel() && env->mp_state == KVM_MP_STATE_HALTED) {
            env->mp_state = KVM_MP_STATE_RUNNABLE;
        }
    }

    if ((cs->interrupt_request & CPU_INTERRUPT_INIT) &&
        !(env->hflags & HF_SMM_MASK)) {
        kvm_cpu_synchronize_state(cs);
        do_cpu_init(cpu);
    }

    if (kvm_irqchip_in_kernel()) {
        return 0;
    }

    if (cs->interrupt_request & CPU_INTERRUPT_POLL) {
        cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
        apic_poll_irq(cpu->apic_state);
    }
    if (((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
         (env->eflags & IF_MASK)) ||
        (cs->interrupt_request & CPU_INTERRUPT_NMI)) {
        cs->halted = 0;
    }
    if (cs->interrupt_request & CPU_INTERRUPT_SIPI) {
        kvm_cpu_synchronize_state(cs);
        do_cpu_sipi(cpu);
    }
    if (cs->interrupt_request & CPU_INTERRUPT_TPR) {
        cs->interrupt_request &= ~CPU_INTERRUPT_TPR;
        kvm_cpu_synchronize_state(cs);
        apic_handle_tpr_access_report(cpu->apic_state, env->eip,
                                      env->tpr_access_type);
    }

    return cs->halted;
}

static int kvm_handle_halt(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;

    if (!((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
          (env->eflags & IF_MASK)) &&
        !(cs->interrupt_request & CPU_INTERRUPT_NMI)) {
        cs->halted = 1;
        return EXCP_HLT;
    }

    return 0;
}

static int kvm_handle_tpr_access(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    struct kvm_run *run = cs->kvm_run;

    apic_handle_tpr_access_report(cpu->apic_state, run->tpr_access.rip,
                                  run->tpr_access.is_write ? TPR_ACCESS_WRITE
                                                           : TPR_ACCESS_READ);
    return 1;
}

int kvm_arch_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    static const uint8_t int3 = 0xcc;

    if (cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn, 1, 0) ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&int3, 1, 1)) {
        return -EINVAL;
    }
    return 0;
}

int kvm_arch_remove_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    uint8_t int3;

    if (cpu_memory_rw_debug(cs, bp->pc, &int3, 1, 0) || int3 != 0xcc ||
        cpu_memory_rw_debug(cs, bp->pc, (uint8_t *)&bp->saved_insn, 1, 1)) {
        return -EINVAL;
    }
    return 0;
}

static struct {
    target_ulong addr;
    int len;
    int type;
} hw_breakpoint[4];

static int nb_hw_breakpoint;

static int find_hw_breakpoint(target_ulong addr, int len, int type)
{
    int n;

    for (n = 0; n < nb_hw_breakpoint; n++) {
        if (hw_breakpoint[n].addr == addr && hw_breakpoint[n].type == type &&
            (hw_breakpoint[n].len == len || len == -1)) {
            return n;
        }
    }
    return -1;
}

int kvm_arch_insert_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    switch (type) {
    case GDB_BREAKPOINT_HW:
        len = 1;
        break;
    case GDB_WATCHPOINT_WRITE:
    case GDB_WATCHPOINT_ACCESS:
        switch (len) {
        case 1:
            break;
        case 2:
        case 4:
        case 8:
            if (addr & (len - 1)) {
                return -EINVAL;
            }
            break;
        default:
            return -EINVAL;
        }
        break;
    default:
        return -ENOSYS;
    }

    if (nb_hw_breakpoint == 4) {
        return -ENOBUFS;
    }
    if (find_hw_breakpoint(addr, len, type) >= 0) {
        return -EEXIST;
    }
    hw_breakpoint[nb_hw_breakpoint].addr = addr;
    hw_breakpoint[nb_hw_breakpoint].len = len;
    hw_breakpoint[nb_hw_breakpoint].type = type;
    nb_hw_breakpoint++;

    return 0;
}

int kvm_arch_remove_hw_breakpoint(target_ulong addr,
                                  target_ulong len, int type)
{
    int n;

    n = find_hw_breakpoint(addr, (type == GDB_BREAKPOINT_HW) ? 1 : len, type);
    if (n < 0) {
        return -ENOENT;
    }
    nb_hw_breakpoint--;
    hw_breakpoint[n] = hw_breakpoint[nb_hw_breakpoint];

    return 0;
}

void kvm_arch_remove_all_hw_breakpoints(void)
{
    nb_hw_breakpoint = 0;
}

static CPUWatchpoint hw_watchpoint;

static int kvm_handle_debug(X86CPU *cpu,
                            struct kvm_debug_exit_arch *arch_info)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    int ret = 0;
    int n;

    if (arch_info->exception == 1) {
        if (arch_info->dr6 & (1 << 14)) {
            if (cs->singlestep_enabled) {
                ret = EXCP_DEBUG;
            }
        } else {
            for (n = 0; n < 4; n++) {
                if (arch_info->dr6 & (1 << n)) {
                    switch ((arch_info->dr7 >> (16 + n*4)) & 0x3) {
                    case 0x0:
                        ret = EXCP_DEBUG;
                        break;
                    case 0x1:
                        ret = EXCP_DEBUG;
                        cs->watchpoint_hit = &hw_watchpoint;
                        hw_watchpoint.virtaddr = hw_breakpoint[n].addr;
                        hw_watchpoint.flags = BP_MEM_WRITE;
                        break;
                    case 0x3:
                        ret = EXCP_DEBUG;
                        cs->watchpoint_hit = &hw_watchpoint;
                        hw_watchpoint.virtaddr = hw_breakpoint[n].addr;
                        hw_watchpoint.flags = BP_MEM_ACCESS;
                        break;
                    }
                }
            }
        }
    } else if (kvm_find_sw_breakpoint(cs, arch_info->pc)) {
        ret = EXCP_DEBUG;
    }
    if (ret == 0) {
        cpu_synchronize_state(cs);
        assert(env->exception_injected == -1);

        /* pass to guest */
        env->exception_injected = arch_info->exception;
        env->has_error_code = 0;
    }

    return ret;
}

void kvm_arch_update_guest_debug(CPUState *cpu, struct kvm_guest_debug *dbg)
{
    const uint8_t type_code[] = {
        [GDB_BREAKPOINT_HW] = 0x0,
        [GDB_WATCHPOINT_WRITE] = 0x1,
        [GDB_WATCHPOINT_ACCESS] = 0x3
    };
    const uint8_t len_code[] = {
        [1] = 0x0, [2] = 0x1, [4] = 0x3, [8] = 0x2
    };
    int n;

    if (kvm_sw_breakpoints_active(cpu)) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }
    if (nb_hw_breakpoint > 0) {
        dbg->control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
        dbg->arch.debugreg[7] = 0x0600;
        for (n = 0; n < nb_hw_breakpoint; n++) {
            dbg->arch.debugreg[n] = hw_breakpoint[n].addr;
            dbg->arch.debugreg[7] |= (2 << (n * 2)) |
                (type_code[hw_breakpoint[n].type] << (16 + n*4)) |
                ((uint32_t)len_code[hw_breakpoint[n].len] << (18 + n*4));
        }
    }
}

static bool host_supports_vmx(void)
{
    uint32_t ecx, unused;

    host_cpuid(1, 0, &unused, &unused, &ecx, &unused);
    return ecx & CPUID_EXT_VMX;
}

#define VMX_INVALID_GUEST_STATE 0x80000021

int kvm_arch_handle_exit(CPUState *cs, struct kvm_run *run)
{
    X86CPU *cpu = X86_CPU(cs);
    uint64_t code;
    int ret;

    switch (run->exit_reason) {
    case KVM_EXIT_HLT:
        DPRINTF("handle_hlt\n");
        qemu_mutex_lock_iothread();
        ret = kvm_handle_halt(cpu);
        qemu_mutex_unlock_iothread();
        break;
    case KVM_EXIT_SET_TPR:
        ret = 0;
        break;
    case KVM_EXIT_TPR_ACCESS:
        qemu_mutex_lock_iothread();
        ret = kvm_handle_tpr_access(cpu);
        qemu_mutex_unlock_iothread();
        break;
    case KVM_EXIT_FAIL_ENTRY:
        code = run->fail_entry.hardware_entry_failure_reason;
        fprintf(stderr, "KVM: entry failed, hardware error 0x%" PRIx64 "\n",
                code);
        if (host_supports_vmx() && code == VMX_INVALID_GUEST_STATE) {
            fprintf(stderr,
                    "\nIf you're running a guest on an Intel machine without "
                        "unrestricted mode\n"
                    "support, the failure can be most likely due to the guest "
                        "entering an invalid\n"
                    "state for Intel VT. For example, the guest maybe running "
                        "in big real mode\n"
                    "which is not supported on less recent Intel processors."
                        "\n\n");
        }
        ret = -1;
        break;
    case KVM_EXIT_EXCEPTION:
        fprintf(stderr, "KVM: exception %d exit (error code 0x%x)\n",
                run->ex.exception, run->ex.error_code);
        ret = -1;
        break;
    case KVM_EXIT_DEBUG:
        DPRINTF("kvm_exit_debug\n");
        qemu_mutex_lock_iothread();
        ret = kvm_handle_debug(cpu, &run->debug.arch);
        qemu_mutex_unlock_iothread();
        break;
    case KVM_EXIT_HYPERV:
        ret = kvm_hv_handle_exit(cpu, &run->hyperv);
        break;
    case KVM_EXIT_IOAPIC_EOI:
        ioapic_eoi_broadcast(run->eoi.vector);
        ret = 0;
        break;
    default:
        fprintf(stderr, "KVM: unknown exit reason %d\n", run->exit_reason);
        ret = -1;
        break;
    }

    return ret;
}

bool kvm_arch_stop_on_emulation_error(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    kvm_cpu_synchronize_state(cs);
    return !(env->cr[0] & CR0_PE_MASK) ||
           ((env->segs[R_CS].selector  & 3) != 3);
}

void kvm_arch_init_irq_routing(KVMState *s)
{
    if (!kvm_check_extension(s, KVM_CAP_IRQ_ROUTING)) {
        /* If kernel can't do irq routing, interrupt source
         * override 0->2 cannot be set up as required by HPET.
         * So we have to disable it.
         */
        no_hpet = 1;
    }
    /* We know at this point that we're using the in-kernel
     * irqchip, so we can use irqfds, and on x86 we know
     * we can use msi via irqfd and GSI routing.
     */
    kvm_msi_via_irqfd_allowed = true;
    kvm_gsi_routing_allowed = true;

    if (kvm_irqchip_is_split()) {
        int i;

        /* If the ioapic is in QEMU and the lapics are in KVM, reserve
           MSI routes for signaling interrupts to the local apics. */
        for (i = 0; i < IOAPIC_NUM_PINS; i++) {
            if (kvm_irqchip_add_msi_route(s, 0, NULL) < 0) {
                error_report("Could not enable split IRQ mode.");
                exit(1);
            }
        }
    }
}

int kvm_arch_irqchip_create(MachineState *ms, KVMState *s)
{
    int ret;
    if (machine_kernel_irqchip_split(ms)) {
        ret = kvm_vm_enable_cap(s, KVM_CAP_SPLIT_IRQCHIP, 0, 24);
        if (ret) {
            error_report("Could not enable split irqchip mode: %s",
                         strerror(-ret));
            exit(1);
        } else {
            DPRINTF("Enabled KVM_CAP_SPLIT_IRQCHIP\n");
            kvm_split_irqchip = true;
            return 1;
        }
    } else {
        return 0;
    }
}

/* Classic KVM device assignment interface. Will remain x86 only. */
int kvm_device_pci_assign(KVMState *s, PCIHostDeviceAddress *dev_addr,
                          uint32_t flags, uint32_t *dev_id)
{
    struct kvm_assigned_pci_dev dev_data = {
        .segnr = dev_addr->domain,
        .busnr = dev_addr->bus,
        .devfn = PCI_DEVFN(dev_addr->slot, dev_addr->function),
        .flags = flags,
    };
    int ret;

    dev_data.assigned_dev_id =
        (dev_addr->domain << 16) | (dev_addr->bus << 8) | dev_data.devfn;

    ret = kvm_vm_ioctl(s, KVM_ASSIGN_PCI_DEVICE, &dev_data);
    if (ret < 0) {
        return ret;
    }

    *dev_id = dev_data.assigned_dev_id;

    return 0;
}

int kvm_device_pci_deassign(KVMState *s, uint32_t dev_id)
{
    struct kvm_assigned_pci_dev dev_data = {
        .assigned_dev_id = dev_id,
    };

    return kvm_vm_ioctl(s, KVM_DEASSIGN_PCI_DEVICE, &dev_data);
}

static int kvm_assign_irq_internal(KVMState *s, uint32_t dev_id,
                                   uint32_t irq_type, uint32_t guest_irq)
{
    struct kvm_assigned_irq assigned_irq = {
        .assigned_dev_id = dev_id,
        .guest_irq = guest_irq,
        .flags = irq_type,
    };

    if (kvm_check_extension(s, KVM_CAP_ASSIGN_DEV_IRQ)) {
        return kvm_vm_ioctl(s, KVM_ASSIGN_DEV_IRQ, &assigned_irq);
    } else {
        return kvm_vm_ioctl(s, KVM_ASSIGN_IRQ, &assigned_irq);
    }
}

int kvm_device_intx_assign(KVMState *s, uint32_t dev_id, bool use_host_msi,
                           uint32_t guest_irq)
{
    uint32_t irq_type = KVM_DEV_IRQ_GUEST_INTX |
        (use_host_msi ? KVM_DEV_IRQ_HOST_MSI : KVM_DEV_IRQ_HOST_INTX);

    return kvm_assign_irq_internal(s, dev_id, irq_type, guest_irq);
}

int kvm_device_intx_set_mask(KVMState *s, uint32_t dev_id, bool masked)
{
    struct kvm_assigned_pci_dev dev_data = {
        .assigned_dev_id = dev_id,
        .flags = masked ? KVM_DEV_ASSIGN_MASK_INTX : 0,
    };

    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_INTX_MASK, &dev_data);
}

static int kvm_deassign_irq_internal(KVMState *s, uint32_t dev_id,
                                     uint32_t type)
{
    struct kvm_assigned_irq assigned_irq = {
        .assigned_dev_id = dev_id,
        .flags = type,
    };

    return kvm_vm_ioctl(s, KVM_DEASSIGN_DEV_IRQ, &assigned_irq);
}

int kvm_device_intx_deassign(KVMState *s, uint32_t dev_id, bool use_host_msi)
{
    return kvm_deassign_irq_internal(s, dev_id, KVM_DEV_IRQ_GUEST_INTX |
        (use_host_msi ? KVM_DEV_IRQ_HOST_MSI : KVM_DEV_IRQ_HOST_INTX));
}

int kvm_device_msi_assign(KVMState *s, uint32_t dev_id, int virq)
{
    return kvm_assign_irq_internal(s, dev_id, KVM_DEV_IRQ_HOST_MSI |
                                              KVM_DEV_IRQ_GUEST_MSI, virq);
}

int kvm_device_msi_deassign(KVMState *s, uint32_t dev_id)
{
    return kvm_deassign_irq_internal(s, dev_id, KVM_DEV_IRQ_GUEST_MSI |
                                                KVM_DEV_IRQ_HOST_MSI);
}

bool kvm_device_msix_supported(KVMState *s)
{
    /* The kernel lacks a corresponding KVM_CAP, so we probe by calling
     * KVM_ASSIGN_SET_MSIX_NR with an invalid parameter. */
    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_MSIX_NR, NULL) == -EFAULT;
}

int kvm_device_msix_init_vectors(KVMState *s, uint32_t dev_id,
                                 uint32_t nr_vectors)
{
    struct kvm_assigned_msix_nr msix_nr = {
        .assigned_dev_id = dev_id,
        .entry_nr = nr_vectors,
    };

    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_MSIX_NR, &msix_nr);
}

int kvm_device_msix_set_vector(KVMState *s, uint32_t dev_id, uint32_t vector,
                               int virq)
{
    struct kvm_assigned_msix_entry msix_entry = {
        .assigned_dev_id = dev_id,
        .gsi = virq,
        .entry = vector,
    };

    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_MSIX_ENTRY, &msix_entry);
}

int kvm_device_msix_assign(KVMState *s, uint32_t dev_id)
{
    return kvm_assign_irq_internal(s, dev_id, KVM_DEV_IRQ_HOST_MSIX |
                                              KVM_DEV_IRQ_GUEST_MSIX, 0);
}

int kvm_device_msix_deassign(KVMState *s, uint32_t dev_id)
{
    return kvm_deassign_irq_internal(s, dev_id, KVM_DEV_IRQ_GUEST_MSIX |
                                                KVM_DEV_IRQ_HOST_MSIX);
}

int kvm_arch_fixup_msi_route(struct kvm_irq_routing_entry *route,
                             uint64_t address, uint32_t data, PCIDevice *dev)
{
    X86IOMMUState *iommu = x86_iommu_get_default();

    if (iommu) {
        int ret;
        MSIMessage src, dst;
        X86IOMMUClass *class = X86_IOMMU_GET_CLASS(iommu);

        src.address = route->u.msi.address_hi;
        src.address <<= VTD_MSI_ADDR_HI_SHIFT;
        src.address |= route->u.msi.address_lo;
        src.data = route->u.msi.data;

        ret = class->int_remap(iommu, &src, &dst, dev ? \
                               pci_requester_id(dev) : \
                               X86_IOMMU_SID_INVALID);
        if (ret) {
            trace_kvm_x86_fixup_msi_error(route->gsi);
            return 1;
        }

        route->u.msi.address_hi = dst.address >> VTD_MSI_ADDR_HI_SHIFT;
        route->u.msi.address_lo = dst.address & VTD_MSI_ADDR_LO_MASK;
        route->u.msi.data = dst.data;
    }

    return 0;
}

typedef struct MSIRouteEntry MSIRouteEntry;

struct MSIRouteEntry {
    PCIDevice *dev;             /* Device pointer */
    int vector;                 /* MSI/MSIX vector index */
    int virq;                   /* Virtual IRQ index */
    QLIST_ENTRY(MSIRouteEntry) list;
};

/* List of used GSI routes */
static QLIST_HEAD(, MSIRouteEntry) msi_route_list = \
    QLIST_HEAD_INITIALIZER(msi_route_list);

static void kvm_update_msi_routes_all(void *private, bool global,
                                      uint32_t index, uint32_t mask)
{
    int cnt = 0;
    MSIRouteEntry *entry;
    MSIMessage msg;
    /* TODO: explicit route update */
    QLIST_FOREACH(entry, &msi_route_list, list) {
        cnt++;
        msg = pci_get_msi_message(entry->dev, entry->vector);
        kvm_irqchip_update_msi_route(kvm_state, entry->virq,
                                     msg, entry->dev);
    }
    kvm_irqchip_commit_routes(kvm_state);
    trace_kvm_x86_update_msi_routes(cnt);
}

int kvm_arch_add_msi_route_post(struct kvm_irq_routing_entry *route,
                                int vector, PCIDevice *dev)
{
    static bool notify_list_inited = false;
    MSIRouteEntry *entry;

    if (!dev) {
        /* These are (possibly) IOAPIC routes only used for split
         * kernel irqchip mode, while what we are housekeeping are
         * PCI devices only. */
        return 0;
    }

    entry = g_new0(MSIRouteEntry, 1);
    entry->dev = dev;
    entry->vector = vector;
    entry->virq = route->gsi;
    QLIST_INSERT_HEAD(&msi_route_list, entry, list);

    trace_kvm_x86_add_msi_route(route->gsi);

    if (!notify_list_inited) {
        /* For the first time we do add route, add ourselves into
         * IOMMU's IEC notify list if needed. */
        X86IOMMUState *iommu = x86_iommu_get_default();
        if (iommu) {
            x86_iommu_iec_register_notifier(iommu,
                                            kvm_update_msi_routes_all,
                                            NULL);
        }
        notify_list_inited = true;
    }
    return 0;
}

int kvm_arch_release_virq_post(int virq)
{
    MSIRouteEntry *entry, *next;
    QLIST_FOREACH_SAFE(entry, &msi_route_list, list, next) {
        if (entry->virq == virq) {
            trace_kvm_x86_remove_msi_route(virq);
            QLIST_REMOVE(entry, list);
            break;
        }
    }
    return 0;
}

int kvm_arch_msi_data_to_gsi(uint32_t data)
{
    abort();
}

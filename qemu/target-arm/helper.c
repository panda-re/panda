#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "gdbstub.h"
#include "helper.h"
#include "qemu-common.h"
#include "host-utils.h"
#include "panda_plugin.h"
#if !defined(CONFIG_USER_ONLY)
#include "hw/loader.h"
#endif

#include "panda_plugin.h"

static uint32_t cortexa9_cp15_c0_c1[8] =
{ 0x1031, 0x11, 0x000, 0, 0x00100103, 0x20000000, 0x01230000, 0x00002111 };

static uint32_t cortexa9_cp15_c0_c2[8] =
{ 0x00101111, 0x13112111, 0x21232041, 0x11112131, 0x00111142, 0, 0, 0 };

static uint32_t cortexa8_cp15_c0_c1[8] =
{ 0x1031, 0x11, 0x400, 0, 0x31100003, 0x20000000, 0x01202000, 0x11 };

static uint32_t cortexa8_cp15_c0_c2[8] =
{ 0x00101111, 0x12112111, 0x21232031, 0x11112131, 0x00111142, 0, 0, 0 };

static uint32_t mpcore_cp15_c0_c1[8] =
{ 0x111, 0x1, 0, 0x2, 0x01100103, 0x10020302, 0x01222000, 0 };

static uint32_t mpcore_cp15_c0_c2[8] =
{ 0x00100011, 0x12002111, 0x11221011, 0x01102131, 0x141, 0, 0, 0 };

static uint32_t arm1136_cp15_c0_c1[8] =
{ 0x111, 0x1, 0x2, 0x3, 0x01130003, 0x10030302, 0x01222110, 0 };

static uint32_t arm1136_cp15_c0_c2[8] =
{ 0x00140011, 0x12002111, 0x11231111, 0x01102131, 0x141, 0, 0, 0 };

static uint32_t arm1176_cp15_c0_c1[8] =
{ 0x111, 0x11, 0x33, 0, 0x01130003, 0x10030302, 0x01222100, 0 };

static uint32_t arm1176_cp15_c0_c2[8] =
{ 0x0140011, 0x12002111, 0x11231121, 0x01102131, 0x01141, 0, 0, 0 };

static uint32_t cpu_arm_find_by_name(const char *name);

static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1u << feature;
}

static void cpu_reset_model_id(CPUARMState *env, uint32_t id)
{
    env->cp15.c0_cpuid = id;
    switch (id) {
    case ARM_CPUID_ARM926:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_VFP);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x41011090;
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM946:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_MPU);
        env->cp15.c0_cachetype = 0x0f004006;
        env->cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_ARM1026:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410110a0;
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00090078;
        break;
    case ARM_CPUID_ARM1136:
        /* This is the 1136 r1, which is a v6K core */
        set_feature(env, ARM_FEATURE_V6K);
        /* Fall through */
    case ARM_CPUID_ARM1136_R2:
        /* What qemu calls "arm1136_r2" is actually the 1136 r0p2, ie an
         * older core than plain "arm1136". In particular this does not
         * have the v6K features.
         */
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        /* These ID register values are correct for 1136 but may be wrong
         * for 1136_r2 (in particular r0p2 does not actually implement most
         * of the ID registers).
         */
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env->cp15.c0_c1, arm1136_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, arm1136_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00050078;
        break;
    case ARM_CPUID_ARM1176:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_VAPA);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410120b5;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env->cp15.c0_c1, arm1176_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, arm1176_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1dd20d2;
        env->cp15.c1_sys = 0x00050078;
        break;
    case ARM_CPUID_ARM11MPCORE:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_VAPA);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410120b4;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11111111;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00000000;
        memcpy(env->cp15.c0_c1, mpcore_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, mpcore_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x1dd20d2;
        break;
    case ARM_CPUID_CORTEXA8:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_THUMB2EE);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x410330c0;
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11110222;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x00011100;
        memcpy(env->cp15.c0_c1, cortexa8_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, cortexa8_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x82048004;
        env->cp15.c0_clid = (1 << 27) | (2 << 24) | 3;
        env->cp15.c0_ccsid[0] = 0xe007e01a; /* 16k L1 dcache. */
        env->cp15.c0_ccsid[1] = 0x2007e01a; /* 16k L1 icache. */
        env->cp15.c0_ccsid[2] = 0xf0000000; /* No L2 icache. */
        env->cp15.c1_sys = 0x00c50078;
        break;
    case ARM_CPUID_CORTEXA9:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_AUXCR);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_VFP_FP16);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_THUMB2EE);
        /* Note that A9 supports the MP extensions even for
         * A9UP and single-core A9MP (which are both different
         * and valid configurations; we don't model A9UP).
         */
        set_feature(env, ARM_FEATURE_V7MP);
        env->vfp.xregs[ARM_VFP_FPSID] = 0x41034000; /* Guess */
        env->vfp.xregs[ARM_VFP_MVFR0] = 0x11110222;
        env->vfp.xregs[ARM_VFP_MVFR1] = 0x01111111;
        memcpy(env->cp15.c0_c1, cortexa9_cp15_c0_c1, 8 * sizeof(uint32_t));
        memcpy(env->cp15.c0_c2, cortexa9_cp15_c0_c2, 8 * sizeof(uint32_t));
        env->cp15.c0_cachetype = 0x80038003;
        env->cp15.c0_clid = (1 << 27) | (1 << 24) | 3;
        env->cp15.c0_ccsid[0] = 0xe00fe015; /* 16k L1 dcache. */
        env->cp15.c0_ccsid[1] = 0x200fe015; /* 16k L1 icache. */
        env->cp15.c1_sys = 0x00c50078;
        break;
    case ARM_CPUID_CORTEXM3:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_M);
        set_feature(env, ARM_FEATURE_THUMB_DIV);
        break;
    case ARM_CPUID_ANY: /* For userspace emulation.  */
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_V6K);
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_VFP);
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_VFP4);
        set_feature(env, ARM_FEATURE_VFP_FP16);
        set_feature(env, ARM_FEATURE_NEON);
        set_feature(env, ARM_FEATURE_THUMB2EE);
        set_feature(env, ARM_FEATURE_ARM_DIV);
        set_feature(env, ARM_FEATURE_V7MP);
        break;
    case ARM_CPUID_TI915T:
    case ARM_CPUID_TI925T:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_OMAPCP);
        env->cp15.c0_cpuid = ARM_CPUID_TI925T; /* Depends on wiring.  */
        env->cp15.c0_cachetype = 0x5109149;
        env->cp15.c1_sys = 0x00000070;
        env->cp15.c15_i_max = 0x000;
        env->cp15.c15_i_min = 0xff0;
        break;
    case ARM_CPUID_PXA250:
    case ARM_CPUID_PXA255:
    case ARM_CPUID_PXA260:
    case ARM_CPUID_PXA261:
    case ARM_CPUID_PXA262:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        env->cp15.c0_cachetype = 0xd172172;
        env->cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_PXA270_A0:
    case ARM_CPUID_PXA270_A1:
    case ARM_CPUID_PXA270_B0:
    case ARM_CPUID_PXA270_B1:
    case ARM_CPUID_PXA270_C0:
    case ARM_CPUID_PXA270_C5:
        set_feature(env, ARM_FEATURE_V4T);
        set_feature(env, ARM_FEATURE_V5);
        set_feature(env, ARM_FEATURE_XSCALE);
        /* JTAG_ID is ((id << 28) | 0x09265013) */
        set_feature(env, ARM_FEATURE_IWMMXT);
        env->iwmmxt.cregs[ARM_IWMMXT_wCID] = 0x69051000 | 'Q';
        env->cp15.c0_cachetype = 0xd172172;
        env->cp15.c1_sys = 0x00000078;
        break;
    case ARM_CPUID_SA1100:
    case ARM_CPUID_SA1110:
        set_feature(env, ARM_FEATURE_STRONGARM);
        env->cp15.c1_sys = 0x00000070;
        break;
    default:
        cpu_abort(env, "Bad CPU ID: %x\n", id);
        break;
    }

    /* Some features automatically imply others: */
    if (arm_feature(env, ARM_FEATURE_V7)) {
        set_feature(env, ARM_FEATURE_VAPA);
    }
    if (arm_feature(env, ARM_FEATURE_ARM_DIV)) {
        set_feature(env, ARM_FEATURE_THUMB_DIV);
    }
}

void cpu_reset(CPUARMState *env)
{
    uint32_t id;

    if (qemu_loglevel_mask(CPU_LOG_RESET)) {
        qemu_log("CPU Reset (CPU %d)\n", env->cpu_index);
        log_cpu_state(env, 0);
    }

    id = env->cp15.c0_cpuid;
    memset(env, 0, offsetof(CPUARMState, breakpoints));
    if (id)
        cpu_reset_model_id(env, id);
#if defined (CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
    /* For user mode we must enable access to coprocessors */
    env->vfp.xregs[ARM_VFP_FPEXC] = 1 << 30;
    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->cp15.c15_cpar = 3;
    } else if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        env->cp15.c15_cpar = 1;
    }
#else
    /* SVC mode with interrupts disabled.  */
    env->uncached_cpsr = ARM_CPU_MODE_SVC | CPSR_A | CPSR_F | CPSR_I;
    /* On ARMv7-M the CPSR_I is the value of the PRIMASK register, and is
       clear at reset.  Initial SP and PC are loaded from ROM.  */
    if (IS_M(env)) {
        uint32_t pc;
        uint8_t *rom;
        env->uncached_cpsr &= ~CPSR_I;
        rom = rom_ptr(0);
        if (rom) {
            /* We should really use ldl_phys here, in case the guest
               modified flash and reset itself.  However images
               loaded via -kernel have not been copied yet, so load the
               values directly from there.  */
            env->regs[13] = ldl_p(rom);
            pc = ldl_p(rom + 4);
            env->thumb = pc & 1;
            env->regs[15] = pc & ~1;
        }
    }
    env->vfp.xregs[ARM_VFP_FPEXC] = 0;
    env->cp15.c2_base_mask = 0xffffc000u;
    /* v7 performance monitor control register: same implementor
     * field as main ID register, and we implement no event counters.
     */
    env->cp15.c9_pmcr = (id & 0xff000000);
#endif
    set_flush_to_zero(1, &env->vfp.standard_fp_status);
    set_flush_inputs_to_zero(1, &env->vfp.standard_fp_status);
    set_default_nan_mode(1, &env->vfp.standard_fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.standard_fp_status);
    tlb_flush(env, 1);
}

static int vfp_gdb_get_reg(CPUState *env, uint8_t *buf, int reg)
{
    int nregs;

    /* VFP data registers are always little-endian.  */
    nregs = arm_feature(env, ARM_FEATURE_VFP3) ? 32 : 16;
    if (reg < nregs) {
        stfq_le_p(buf, env->vfp.regs[reg]);
        return 8;
    }
    if (arm_feature(env, ARM_FEATURE_NEON)) {
        /* Aliases for Q regs.  */
        nregs += 16;
        if (reg < nregs) {
            stfq_le_p(buf, env->vfp.regs[(reg - 32) * 2]);
            stfq_le_p(buf + 8, env->vfp.regs[(reg - 32) * 2 + 1]);
            return 16;
        }
    }
    switch (reg - nregs) {
    case 0: stl_p(buf, env->vfp.xregs[ARM_VFP_FPSID]); return 4;
    case 1: stl_p(buf, env->vfp.xregs[ARM_VFP_FPSCR]); return 4;
    case 2: stl_p(buf, env->vfp.xregs[ARM_VFP_FPEXC]); return 4;
    }
    return 0;
}

static int vfp_gdb_set_reg(CPUState *env, uint8_t *buf, int reg)
{
    int nregs;

    nregs = arm_feature(env, ARM_FEATURE_VFP3) ? 32 : 16;
    if (reg < nregs) {
        env->vfp.regs[reg] = ldfq_le_p(buf);
        return 8;
    }
    if (arm_feature(env, ARM_FEATURE_NEON)) {
        nregs += 16;
        if (reg < nregs) {
            env->vfp.regs[(reg - 32) * 2] = ldfq_le_p(buf);
            env->vfp.regs[(reg - 32) * 2 + 1] = ldfq_le_p(buf + 8);
            return 16;
        }
    }
    switch (reg - nregs) {
    case 0: env->vfp.xregs[ARM_VFP_FPSID] = ldl_p(buf); return 4;
    case 1: env->vfp.xregs[ARM_VFP_FPSCR] = ldl_p(buf); return 4;
    case 2: env->vfp.xregs[ARM_VFP_FPEXC] = ldl_p(buf) & (1 << 30); return 4;
    }
    return 0;
}

#ifdef CONFIG_LLVM
extern CPUARMState *env;
#endif

CPUARMState *cpu_arm_init(const char *cpu_model)
{
#ifndef CONFIG_LLVM
    CPUARMState *env;
#endif
    uint32_t id;
    static int inited = 0;

    id = cpu_arm_find_by_name(cpu_model);
    if (id == 0)
        return NULL;
    env = g_malloc0(sizeof(CPUARMState));
    cpu_exec_init(env);
    if (!inited) {
        inited = 1;
        arm_translate_init();
    }

    env->cpu_model_str = cpu_model;
    env->cp15.c0_cpuid = id;
    cpu_reset(env);
    if (arm_feature(env, ARM_FEATURE_NEON)) {
        gdb_register_coprocessor(env, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 51, "arm-neon.xml", 0);
    } else if (arm_feature(env, ARM_FEATURE_VFP3)) {
        gdb_register_coprocessor(env, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 35, "arm-vfp3.xml", 0);
    } else if (arm_feature(env, ARM_FEATURE_VFP)) {
        gdb_register_coprocessor(env, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 19, "arm-vfp.xml", 0);
    }
    qemu_init_vcpu(env);
    return env;
}

struct arm_cpu_t {
    uint32_t id;
    const char *name;
};

static const struct arm_cpu_t arm_cpu_names[] = {
    { ARM_CPUID_ARM926, "arm926"},
    { ARM_CPUID_ARM946, "arm946"},
    { ARM_CPUID_ARM1026, "arm1026"},
    { ARM_CPUID_ARM1136, "arm1136"},
    { ARM_CPUID_ARM1136_R2, "arm1136-r2"},
    { ARM_CPUID_ARM1176, "arm1176"},
    { ARM_CPUID_ARM11MPCORE, "arm11mpcore"},
    { ARM_CPUID_CORTEXM3, "cortex-m3"},
    { ARM_CPUID_CORTEXA8, "cortex-a8"},
    { ARM_CPUID_CORTEXA9, "cortex-a9"},
    { ARM_CPUID_TI925T, "ti925t" },
    { ARM_CPUID_PXA250, "pxa250" },
    { ARM_CPUID_SA1100,    "sa1100" },
    { ARM_CPUID_SA1110,    "sa1110" },
    { ARM_CPUID_PXA255, "pxa255" },
    { ARM_CPUID_PXA260, "pxa260" },
    { ARM_CPUID_PXA261, "pxa261" },
    { ARM_CPUID_PXA262, "pxa262" },
    { ARM_CPUID_PXA270, "pxa270" },
    { ARM_CPUID_PXA270_A0, "pxa270-a0" },
    { ARM_CPUID_PXA270_A1, "pxa270-a1" },
    { ARM_CPUID_PXA270_B0, "pxa270-b0" },
    { ARM_CPUID_PXA270_B1, "pxa270-b1" },
    { ARM_CPUID_PXA270_C0, "pxa270-c0" },
    { ARM_CPUID_PXA270_C5, "pxa270-c5" },
    { ARM_CPUID_ANY, "any"},
    { 0, NULL}
};

void arm_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
    int i;

    (*cpu_fprintf)(f, "Available CPUs:\n");
    for (i = 0; arm_cpu_names[i].name; i++) {
        (*cpu_fprintf)(f, "  %s\n", arm_cpu_names[i].name);
    }
}

/* return 0 if not found */
static uint32_t cpu_arm_find_by_name(const char *name)
{
    int i;
    uint32_t id;

    id = 0;
    for (i = 0; arm_cpu_names[i].name; i++) {
        if (strcmp(name, arm_cpu_names[i].name) == 0) {
            id = arm_cpu_names[i].id;
            break;
        }
    }
    return id;
}

void cpu_arm_close(CPUARMState *env)
{
    g_free(env);
}

uint32_t cpsr_read(CPUARMState *env)
{
    int ZF;
    ZF = (env->ZF == 0);
    return env->uncached_cpsr | (env->NF & 0x80000000) | (ZF << 30) |
        (env->CF << 29) | ((env->VF & 0x80000000) >> 3) | (env->QF << 27)
        | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
        | ((env->condexec_bits & 0xfc) << 8)
        | (env->GE << 16);
}

void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask)
{
    if (mask & CPSR_NZCV) {
        env->ZF = (~val) & CPSR_Z;
        env->NF = val;
        env->CF = (val >> 29) & 1;
        env->VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    if ((env->uncached_cpsr ^ val) & mask & CPSR_M) {
        switch_mode(env, val & CPSR_M);
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}

/* Sign/zero extend */
uint32_t HELPER(sxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(int8_t)x;
    res |= (uint32_t)(int8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(uxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(uint8_t)x;
    res |= (uint32_t)(uint8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(clz)(uint32_t x)
{
    return clz32(x);
}

int32_t HELPER(sdiv)(int32_t num, int32_t den)
{
    if (den == 0)
      return 0;
    if (num == INT_MIN && den == -1)
      return INT_MIN;
    return num / den;
}

uint32_t HELPER(udiv)(uint32_t num, uint32_t den)
{
    if (den == 0)
      return 0;
    return num / den;
}

uint32_t HELPER(rbit)(uint32_t x)
{
    x =  ((x & 0xff000000) >> 24)
       | ((x & 0x00ff0000) >> 8)
       | ((x & 0x0000ff00) << 8)
       | ((x & 0x000000ff) << 24);
    x =  ((x & 0xf0f0f0f0) >> 4)
       | ((x & 0x0f0f0f0f) << 4);
    x =  ((x & 0x88888888) >> 3)
       | ((x & 0x44444444) >> 1)
       | ((x & 0x22222222) << 1)
       | ((x & 0x11111111) << 3);
    return x;
}

uint32_t HELPER(abs)(uint32_t x)
{
    return ((int32_t)x < 0) ? -x : x;
}

#if defined(CONFIG_USER_ONLY)

void do_interrupt (CPUState *env)
{
    env->exception_index = -1;
}

int cpu_arm_handle_mmu_fault (CPUState *env, target_ulong address, int rw,
                              int mmu_idx)
{
    if (rw == 2) {
        env->exception_index = EXCP_PREFETCH_ABORT;
        env->cp15.c6_insn = address;
    } else {
        env->exception_index = EXCP_DATA_ABORT;
        env->cp15.c6_data = address;
    }
    return 1;
}

/* These should probably raise undefined insn exceptions.  */
void HELPER(set_cp)(CPUState *env, uint32_t insn, uint32_t val)
{
    int op1 = (insn >> 8) & 0xf;
    if (op1 == 7){
        // PANDA instrumentation: guest hypercall
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_GUEST_HYPERCALL]; plist != NULL;
                plist = plist->next){
            plist->entry.guest_hypercall(env);
        }
    }
    else {
        cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    }
    return;
}

uint32_t HELPER(get_cp)(CPUState *env, uint32_t insn)
{
    int op1 = (insn >> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return 0;
}

void HELPER(set_cp15)(CPUState *env, uint32_t insn, uint32_t val)
{
    cpu_abort(env, "cp15 insn %08x\n", insn);
}

uint32_t HELPER(get_cp15)(CPUState *env, uint32_t insn)
{
    cpu_abort(env, "cp15 insn %08x\n", insn);
}

/* These should probably raise undefined insn exceptions.  */
void HELPER(v7m_msr)(CPUState *env, uint32_t reg, uint32_t val)
{
    cpu_abort(env, "v7m_mrs %d\n", reg);
}

uint32_t HELPER(v7m_mrs)(CPUState *env, uint32_t reg)
{
    cpu_abort(env, "v7m_mrs %d\n", reg);
    return 0;
}

void switch_mode(CPUState *env, int mode)
{
    if (mode != ARM_CPU_MODE_USR)
        cpu_abort(env, "Tried to switch out of user mode\n");
}

void HELPER(set_r13_banked)(CPUState *env, uint32_t mode, uint32_t val)
{
    cpu_abort(env, "banked r13 write\n");
}

uint32_t HELPER(get_r13_banked)(CPUState *env, uint32_t mode)
{
    cpu_abort(env, "banked r13 read\n");
    return 0;
}

#else

extern int semihosting_enabled;

/* Map CPU modes onto saved register banks.  */
static inline int bank_number (CPUState *env, int mode)
{
    switch (mode) {
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
        return 0;
    case ARM_CPU_MODE_SVC:
        return 1;
    case ARM_CPU_MODE_ABT:
        return 2;
    case ARM_CPU_MODE_UND:
        return 3;
    case ARM_CPU_MODE_IRQ:
        return 4;
    case ARM_CPU_MODE_FIQ:
        return 5;
    }
    cpu_abort(env, "Bad mode %x\n", mode);
    return -1;
}

void switch_mode(CPUState *env, int mode)
{
    int old_mode;
    int i;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
    } else if (mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    }

    i = bank_number(env, old_mode);
    env->banked_r13[i] = env->regs[13];
    env->banked_r14[i] = env->regs[14];
    env->banked_spsr[i] = env->spsr;

    i = bank_number(env, mode);
    env->regs[13] = env->banked_r13[i];
    env->regs[14] = env->banked_r14[i];
    env->spsr = env->banked_spsr[i];
}

static void v7m_push(CPUARMState *env, uint32_t val)
{
    env->regs[13] -= 4;
    stl_phys(env->regs[13], val);
}

static uint32_t v7m_pop(CPUARMState *env)
{
    uint32_t val;
    val = ldl_phys(env->regs[13]);
    env->regs[13] += 4;
    return val;
}

/* Switch to V7M main or process stack pointer.  */
static void switch_v7m_sp(CPUARMState *env, int process)
{
    uint32_t tmp;
    if (env->v7m.current_sp != process) {
        tmp = env->v7m.other_sp;
        env->v7m.other_sp = env->regs[13];
        env->regs[13] = tmp;
        env->v7m.current_sp = process;
    }
}

static void do_v7m_exception_exit(CPUARMState *env)
{
    uint32_t type;
    uint32_t xpsr;

    type = env->regs[15];
    if (env->v7m.exception != 0)
        armv7m_nvic_complete_irq(env->nvic, env->v7m.exception);

    /* Switch to the target stack.  */
    switch_v7m_sp(env, (type & 4) != 0);
    /* Pop registers.  */
    env->regs[0] = v7m_pop(env);
    env->regs[1] = v7m_pop(env);
    env->regs[2] = v7m_pop(env);
    env->regs[3] = v7m_pop(env);
    env->regs[12] = v7m_pop(env);
    env->regs[14] = v7m_pop(env);
    env->regs[15] = v7m_pop(env);
    xpsr = v7m_pop(env);
    xpsr_write(env, xpsr, 0xfffffdff);
    /* Undo stack alignment.  */
    if (xpsr & 0x200)
        env->regs[13] |= 4;
    /* ??? The exception return type specifies Thread/Handler mode.  However
       this is also implied by the xPSR value. Not sure what to do
       if there is a mismatch.  */
    /* ??? Likewise for mismatches between the CONTROL register and the stack
       pointer.  */
}

static void do_interrupt_v7m(CPUARMState *env)
{
    uint32_t xpsr = xpsr_read(env);
    uint32_t lr;
    uint32_t addr;

    lr = 0xfffffff1;
    if (env->v7m.current_sp)
        lr |= 4;
    if (env->v7m.exception == 0)
        lr |= 8;

    /* For exceptions we just mark as pending on the NVIC, and let that
       handle it.  */
    /* TODO: Need to escalate if the current priority is higher than the
       one we're raising.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_USAGE);
        return;
    case EXCP_SWI:
        env->regs[15] += 2;
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_SVC);
        return;
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_MEM);
        return;
    case EXCP_BKPT:
        if (semihosting_enabled) {
            int nr;
            nr = lduw_code(env->regs[15]) & 0xff;
            if (nr == 0xab) {
                env->regs[15] += 2;
                env->regs[0] = do_arm_semihosting(env);
                return;
            }
        }
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_DEBUG);
        return;
    case EXCP_IRQ:
        env->v7m.exception = armv7m_nvic_acknowledge_irq(env->nvic);
        break;
    case EXCP_EXCEPTION_EXIT:
        do_v7m_exception_exit(env);
        return;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    /* Align stack pointer.  */
    /* ??? Should only do this if Configuration Control Register
       STACKALIGN bit is set.  */
    if (env->regs[13] & 4) {
        env->regs[13] -= 4;
        xpsr |= 0x200;
    }
    /* Switch to the handler mode.  */
    v7m_push(env, xpsr);
    v7m_push(env, env->regs[15]);
    v7m_push(env, env->regs[14]);
    v7m_push(env, env->regs[12]);
    v7m_push(env, env->regs[3]);
    v7m_push(env, env->regs[2]);
    v7m_push(env, env->regs[1]);
    v7m_push(env, env->regs[0]);
    switch_v7m_sp(env, 0);
    env->uncached_cpsr &= ~CPSR_IT;
    env->regs[14] = lr;
    addr = ldl_phys(env->v7m.vecbase + env->v7m.exception * 4);
    env->regs[15] = addr & 0xfffffffe;
    env->thumb = addr & 1;
}

/* Handle a CPU exception.  */
void do_interrupt(CPUARMState *env)
{
    uint32_t addr;
    uint32_t mask;
    int new_mode;
    uint32_t offset;

    if (IS_M(env)) {
        do_interrupt_v7m(env);
        return;
    }
    /* TODO: Vectored interrupt controller.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        new_mode = ARM_CPU_MODE_UND;
        addr = 0x04;
        mask = CPSR_I;
        if (env->thumb)
            offset = 2;
        else
            offset = 4;
        break;
    case EXCP_SWI:
        if (semihosting_enabled) {
            /* Check for semihosting interrupt.  */
            if (env->thumb) {
                mask = lduw_code(env->regs[15] - 2) & 0xff;
            } else {
                mask = ldl_code(env->regs[15] - 4) & 0xffffff;
            }
            /* Only intercept calls from privileged modes, to provide some
               semblance of security.  */
            if (((mask == 0x123456 && !env->thumb)
                    || (mask == 0xab && env->thumb))
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                env->regs[0] = do_arm_semihosting(env);
                return;
            }
        }
        new_mode = ARM_CPU_MODE_SVC;
        addr = 0x08;
        mask = CPSR_I;
        /* The PC already points to the next instruction.  */
        offset = 0;
        break;
    case EXCP_BKPT:
        /* See if this is a semihosting syscall.  */
        if (env->thumb && semihosting_enabled) {
            mask = lduw_code(env->regs[15]) & 0xff;
            if (mask == 0xab
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                env->regs[15] += 2;
                env->regs[0] = do_arm_semihosting(env);
                return;
            }
        }
        env->cp15.c5_insn = 2;
        /* Fall through to prefetch abort.  */
    case EXCP_PREFETCH_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x0c;
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_DATA_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x10;
        mask = CPSR_A | CPSR_I;
        offset = 8;
        break;
    case EXCP_IRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_FIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 4;
        break;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }
    /* High vectors.  */
    if (env->cp15.c1_sys & (1 << 13)) {
        addr += 0xffff0000;
    }
    switch_mode (env, new_mode);
    env->spsr = cpsr_read(env);
    /* Clear IT bits.  */
    env->condexec_bits = 0;
    /* Switch to the new mode, and to the correct instruction set.  */
    env->uncached_cpsr = (env->uncached_cpsr & ~CPSR_M) | new_mode;
    env->uncached_cpsr |= mask;
    /* this is a lie, as the was no c1_sys on V4T/V5, but who cares
     * and we should just guard the thumb mode on V4 */
    if (arm_feature(env, ARM_FEATURE_V4T)) {
        env->thumb = (env->cp15.c1_sys & (1 << 30)) != 0;
    }
    env->regs[14] = env->regs[15] + offset;
    env->regs[15] = addr;
    env->interrupt_request |= CPU_INTERRUPT_EXITTB;
}

/* Check section/page access permissions.
   Returns the page protection flags, or zero if the access is not
   permitted.  */
static inline int check_ap(CPUState *env, int ap, int domain, int access_type,
                           int is_user)
{
  int prot_ro;

  if (domain == 3)
    return PAGE_READ | PAGE_WRITE;

  if (access_type == 1)
      prot_ro = 0;
  else
      prot_ro = PAGE_READ;

  switch (ap) {
  case 0:
      if (access_type == 1)
          return 0;
      switch ((env->cp15.c1_sys >> 8) & 3) {
      case 1:
          return is_user ? 0 : PAGE_READ;
      case 2:
          return PAGE_READ;
      default:
          return 0;
      }
  case 1:
      return is_user ? 0 : PAGE_READ | PAGE_WRITE;
  case 2:
      if (is_user)
          return prot_ro;
      else
          return PAGE_READ | PAGE_WRITE;
  case 3:
      return PAGE_READ | PAGE_WRITE;
  case 4: /* Reserved.  */
      return 0;
  case 5:
      return is_user ? 0 : prot_ro;
  case 6:
      return prot_ro;
  case 7:
      if (!arm_feature (env, ARM_FEATURE_V6K))
          return 0;
      return prot_ro;
  default:
      abort();
  }
}

static uint32_t get_level1_table_address(CPUState *env, uint32_t address)
{
    uint32_t table;

    if (address & env->cp15.c2_mask)
        table = env->cp15.c2_base1 & 0xffffc000;
    else
        table = env->cp15.c2_base0 & env->cp15.c2_base_mask;

    table |= (address >> 18) & 0x3ffc;
    return table;
}

static int get_phys_addr_v5(CPUState *env, uint32_t address, int access_type,
			    int is_user, uint32_t *phys_ptr, int *prot,
                            target_ulong *page_size)
{
    int code;
    uint32_t table;
    uint32_t desc;
    int type;
    int ap;
    int domain;
    uint32_t phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    table = get_level1_table_address(env, address);
    desc = ldl_phys(table);
    type = (desc & 3);
    domain = (env->cp15.c3 >> ((desc >> 4) & 0x1e)) & 3;
    if (type == 0) {
        /* Section translation fault.  */
        code = 5;
        goto do_fault;
    }
    if (domain == 0 || domain == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        /* 1Mb section.  */
        phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
        ap = (desc >> 10) & 3;
        code = 13;
        *page_size = 1024 * 1024;
    } else {
        /* Lookup l2 entry.  */
	if (type == 1) {
	    /* Coarse pagetable.  */
	    table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
	} else {
	    /* Fine pagetable.  */
	    table = (desc & 0xfffff000) | ((address >> 8) & 0xffc);
	}
        desc = ldl_phys(table);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            *page_size = 0x10000;
            break;
        case 2: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            *page_size = 0x1000;
            break;
        case 3: /* 1k page.  */
	    if (type == 1) {
		if (arm_feature(env, ARM_FEATURE_XSCALE)) {
		    phys_addr = (desc & 0xfffff000) | (address & 0xfff);
		} else {
		    /* Page translation fault.  */
		    code = 7;
		    goto do_fault;
		}
	    } else {
		phys_addr = (desc & 0xfffffc00) | (address & 0x3ff);
	    }
            ap = (desc >> 4) & 3;
            *page_size = 0x400;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    *prot = check_ap(env, ap, domain, access_type, is_user);
    if (!*prot) {
        /* Access permission fault.  */
        goto do_fault;
    }
    *prot |= PAGE_EXEC;
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

static int get_phys_addr_v6(CPUState *env, uint32_t address, int access_type,
			    int is_user, uint32_t *phys_ptr, int *prot,
                            target_ulong *page_size)
{
    int code;
    uint32_t table;
    uint32_t desc;
    uint32_t xn;
    int type;
    int ap;
    int domain;
    uint32_t phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    table = get_level1_table_address(env, address);
    desc = ldl_phys(table);
    type = (desc & 3);
    if (type == 0) {
        /* Section translation fault.  */
        code = 5;
        domain = 0;
        goto do_fault;
    } else if (type == 2 && (desc & (1 << 18))) {
        /* Supersection.  */
        domain = 0;
    } else {
        /* Section or page.  */
        domain = (desc >> 4) & 0x1e;
    }
    domain = (env->cp15.c3 >> domain) & 3;
    if (domain == 0 || domain == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        if (desc & (1 << 18)) {
            /* Supersection.  */
            phys_addr = (desc & 0xff000000) | (address & 0x00ffffff);
            *page_size = 0x1000000;
        } else {
            /* Section.  */
            phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
            *page_size = 0x100000;
        }
        ap = ((desc >> 10) & 3) | ((desc >> 13) & 4);
        xn = desc & (1 << 4);
        code = 13;
    } else {
        /* Lookup l2 entry.  */
        table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
        desc = ldl_phys(table);
        ap = ((desc >> 4) & 3) | ((desc >> 7) & 4);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            xn = desc & (1 << 15);
            *page_size = 0x10000;
            break;
        case 2: case 3: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            xn = desc & 1;
            *page_size = 0x1000;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    if (domain == 3) {
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    } else {
        if (xn && access_type == 2)
            goto do_fault;

        /* The simplified model uses AP[0] as an access control bit.  */
        if ((env->cp15.c1_sys & (1 << 29)) && (ap & 1) == 0) {
            /* Access flag fault.  */
            code = (code == 15) ? 6 : 3;
            goto do_fault;
        }
        *prot = check_ap(env, ap, domain, access_type, is_user);
        if (!*prot) {
            /* Access permission fault.  */
            goto do_fault;
        }
        if (!xn) {
            *prot |= PAGE_EXEC;
        }
    }
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

static int get_phys_addr_mpu(CPUState *env, uint32_t address, int access_type,
			     int is_user, uint32_t *phys_ptr, int *prot)
{
    int n;
    uint32_t mask;
    uint32_t base;

    *phys_ptr = address;
    for (n = 7; n >= 0; n--) {
	base = env->cp15.c6_region[n];
	if ((base & 1) == 0)
	    continue;
	mask = 1 << ((base >> 1) & 0x1f);
	/* Keep this shift separate from the above to avoid an
	   (undefined) << 32.  */
	mask = (mask << 1) - 1;
	if (((base ^ address) & ~mask) == 0)
	    break;
    }
    if (n < 0)
	return 2;

    if (access_type == 2) {
	mask = env->cp15.c5_insn;
    } else {
	mask = env->cp15.c5_data;
    }
    mask = (mask >> (n * 4)) & 0xf;
    switch (mask) {
    case 0:
	return 1;
    case 1:
	if (is_user)
	  return 1;
	*prot = PAGE_READ | PAGE_WRITE;
	break;
    case 2:
	*prot = PAGE_READ;
	if (!is_user)
	    *prot |= PAGE_WRITE;
	break;
    case 3:
	*prot = PAGE_READ | PAGE_WRITE;
	break;
    case 5:
	if (is_user)
	    return 1;
	*prot = PAGE_READ;
	break;
    case 6:
	*prot = PAGE_READ;
	break;
    default:
	/* Bad permission.  */
	return 1;
    }
    *prot |= PAGE_EXEC;
    return 0;
}

static inline int get_phys_addr(CPUState *env, uint32_t address,
                                int access_type, int is_user,
                                uint32_t *phys_ptr, int *prot,
                                target_ulong *page_size)
{
    /* Fast Context Switch Extension.  */
    if (address < 0x02000000)
        address += env->cp15.c13_fcse;

    if ((env->cp15.c1_sys & 1) == 0) {
        /* MMU/MPU disabled.  */
        *phys_ptr = address;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        *page_size = TARGET_PAGE_SIZE;
        return 0;
    } else if (arm_feature(env, ARM_FEATURE_MPU)) {
        *page_size = TARGET_PAGE_SIZE;
	return get_phys_addr_mpu(env, address, access_type, is_user, phys_ptr,
				 prot);
    } else if (env->cp15.c1_sys & (1 << 23)) {
        return get_phys_addr_v6(env, address, access_type, is_user, phys_ptr,
                                prot, page_size);
    } else {
        return get_phys_addr_v5(env, address, access_type, is_user, phys_ptr,
                                prot, page_size);
    }
}

int cpu_arm_handle_mmu_fault (CPUState *env, target_ulong address,
                              int access_type, int mmu_idx)
{
    uint32_t phys_addr;
    target_ulong page_size;
    int prot;
    int ret, is_user;

    is_user = mmu_idx == MMU_USER_IDX;
    ret = get_phys_addr(env, address, access_type, is_user, &phys_addr, &prot,
                        &page_size);
    if (ret == 0) {
        /* Map a single [sub]page.  */
        phys_addr &= ~(uint32_t)0x3ff;
        address &= ~(uint32_t)0x3ff;
        tlb_set_page (env, address, phys_addr, prot, mmu_idx, page_size);
        return 0;
    }

    if (access_type == 2) {
        env->cp15.c5_insn = ret;
        env->cp15.c6_insn = address;
        env->exception_index = EXCP_PREFETCH_ABORT;
    } else {
        env->cp15.c5_data = ret;
        if (access_type == 1 && arm_feature(env, ARM_FEATURE_V6))
            env->cp15.c5_data |= (1 << 11);
        env->cp15.c6_data = address;
        env->exception_index = EXCP_DATA_ABORT;
    }
    return 1;
}

target_phys_addr_t cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    uint32_t phys_addr;
    target_ulong page_size;
    int prot;
    int ret;

    ret = get_phys_addr(env, addr, 0, 0, &phys_addr, &prot, &page_size);

    if (ret != 0)
        return -1;

    return phys_addr;
}

target_phys_addr_t cpu_get_phys_addr(CPUState *env, target_ulong addr){
    // rwhelan: appears it actually returns the address for ARM
    return cpu_get_phys_page_debug(env, addr);
}

void HELPER(set_cp)(CPUState *env, uint32_t insn, uint32_t val)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int src = (insn >> 16) & 0xf;
    int operand = insn & 0xf;
    
    if (env->cp[cp_num].cp_write)
        env->cp[cp_num].cp_write(env->cp[cp_num].opaque,
                                 cp_info, src, operand, val);
    
    if (cp_num == 7){
        // PANDA instrumentation: guest hypercall
        panda_cb_list *plist;
        for (plist = panda_cbs[PANDA_CB_GUEST_HYPERCALL]; plist != NULL;
                plist = plist->next){
            plist->entry.guest_hypercall(env);
        }
    }
}

uint32_t HELPER(get_cp)(CPUState *env, uint32_t insn)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int dest = (insn >> 16) & 0xf;
    int operand = insn & 0xf;

    if (env->cp[cp_num].cp_read)
        return env->cp[cp_num].cp_read(env->cp[cp_num].opaque,
                                       cp_info, dest, operand);
    return 0;
}

/* Return basic MPU access permission bits.  */
static uint32_t simple_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val >> i) & mask;
        mask <<= 2;
    }
    return ret;
}

/* Pad basic MPU access permission bits to extended format.  */
static uint32_t extended_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val & mask) << i;
        mask <<= 2;
    }
    return ret;
}

void HELPER(set_cp15)(CPUState *env, uint32_t insn, uint32_t val)
{
    int op1;
    int op2;
    int crm;

    panda_cb_list *plist;
    target_ulong oldval;

    op1 = (insn >> 21) & 7;
    op2 = (insn >> 5) & 7;
    crm = insn & 0xf;
    switch ((insn >> 16) & 0xf) {
    case 0:
        /* ID codes.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE))
            break;
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            break;
        if (arm_feature(env, ARM_FEATURE_V7)
                && op1 == 2 && crm == 0 && op2 == 0) {
            env->cp15.c0_cssel = val & 0xf;
            break;
        }
        goto bad_reg;
    case 1: /* System configuration.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (!arm_feature(env, ARM_FEATURE_XSCALE) || crm == 0)
                env->cp15.c1_sys = val;
            /* ??? Lots of these bits are not implemented.  */
            /* This may enable/disable the MMU, so do a TLB flush.  */
            tlb_flush(env, 1);
            break;
        case 1: /* Auxiliary control register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE)) {
                env->cp15.c1_xscaleauxcr = val;
                break;
            }
            /* Not implemented.  */
            break;
        case 2:
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                goto bad_reg;
            if (env->cp15.c1_coproc != val) {
                env->cp15.c1_coproc = val;
                /* ??? Is this safe when called from within a TB?  */
                panda_do_flush_tb();
                //tb_flush(env);
            }
            break;
        default:
            goto bad_reg;
        }
        break;
    case 2: /* MMU Page table control / MPU cache control.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            switch (op2) {
            case 0:
                env->cp15.c2_data = val;
                break;
            case 1:
                env->cp15.c2_insn = val;
                break;
            default:
                goto bad_reg;
            }
        } else {
	    switch (op2) {
	    case 0:
                oldval = env->cp15.c2_base0;
		for(plist = panda_cbs[PANDA_CB_VMI_PGD_CHANGED]; plist != NULL; plist = plist->next) {
                    plist->entry.after_PGD_write(env, oldval, val);
		}
		env->cp15.c2_base0 = val;
		break;
	    case 1:
                oldval = env->cp15.c2_base1;
		for(plist = panda_cbs[PANDA_CB_VMI_PGD_CHANGED]; plist != NULL; plist = plist->next) {
                    plist->entry.after_PGD_write(env, oldval, val);
		}
		env->cp15.c2_base1 = val;
		break;
	    case 2:
                val &= 7;
                env->cp15.c2_control = val;
		env->cp15.c2_mask = ~(((uint32_t)0xffffffffu) >> val);
                env->cp15.c2_base_mask = ~((uint32_t)0x3fffu >> val);
		break;
	    default:
		goto bad_reg;
	    }
        }
        break;
    case 3: /* MMU Domain access control / MPU write buffer control.  */
        env->cp15.c3 = val;
        tlb_flush(env, 1); /* Flush TLB as domain not tracked in TLB */
        break;
    case 4: /* Reserved.  */
        goto bad_reg;
    case 5: /* MMU Fault status / MPU access permission.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (arm_feature(env, ARM_FEATURE_MPU))
                val = extended_mpu_ap_bits(val);
            env->cp15.c5_data = val;
            break;
        case 1:
            if (arm_feature(env, ARM_FEATURE_MPU))
                val = extended_mpu_ap_bits(val);
            env->cp15.c5_insn = val;
            break;
        case 2:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            env->cp15.c5_data = val;
            break;
        case 3:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            env->cp15.c5_insn = val;
            break;
        default:
            goto bad_reg;
        }
        break;
    case 6: /* MMU Fault address / MPU base/size.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            if (crm >= 8)
                goto bad_reg;
            env->cp15.c6_region[crm] = val;
        } else {
            if (arm_feature(env, ARM_FEATURE_OMAPCP))
                op2 = 0;
            switch (op2) {
            case 0:
                env->cp15.c6_data = val;
                break;
            case 1: /* ??? This is WFAR on armv6 */
            case 2:
                env->cp15.c6_insn = val;
                break;
            default:
                goto bad_reg;
            }
        }
        break;
    case 7: /* Cache control.  */
        env->cp15.c15_i_max = 0x000;
        env->cp15.c15_i_min = 0xff0;
        if (op1 != 0) {
            goto bad_reg;
        }
        /* No cache, so nothing to do except VA->PA translations. */
        if (arm_feature(env, ARM_FEATURE_VAPA)) {
            switch (crm) {
            case 4:
                if (arm_feature(env, ARM_FEATURE_V7)) {
                    env->cp15.c7_par = val & 0xfffff6ff;
                } else {
                    env->cp15.c7_par = val & 0xfffff1ff;
                }
                break;
            case 8: {
                uint32_t phys_addr;
                target_ulong page_size;
                int prot;
                int ret, is_user = op2 & 2;
                int access_type = op2 & 1;

                if (op2 & 4) {
                    /* Other states are only available with TrustZone */
                    goto bad_reg;
                }
                ret = get_phys_addr(env, val, access_type, is_user,
                                    &phys_addr, &prot, &page_size);
                if (ret == 0) {
                    /* We do not set any attribute bits in the PAR */
                    if (page_size == (1 << 24)
                        && arm_feature(env, ARM_FEATURE_V7)) {
                        env->cp15.c7_par = (phys_addr & 0xff000000) | 1 << 1;
                    } else {
                        env->cp15.c7_par = phys_addr & 0xfffff000;
                    }
                } else {
                    env->cp15.c7_par = ((ret & (10 << 1)) >> 5) |
                                       ((ret & (12 << 1)) >> 6) |
                                       ((ret & 0xf) << 1) | 1;
                }
                break;
            }
            }
        }
        break;
    case 8: /* MMU TLB control.  */
        switch (op2) {
        case 0: /* Invalidate all.  */
            tlb_flush(env, 0);
            break;
        case 1: /* Invalidate single TLB entry.  */
            tlb_flush_page(env, val & TARGET_PAGE_MASK);
            break;
        case 2: /* Invalidate on ASID.  */
            tlb_flush(env, val == 0);
            break;
        case 3: /* Invalidate single entry on MVA.  */
            /* ??? This is like case 1, but ignores ASID.  */
            tlb_flush(env, 1);
            break;
        default:
            goto bad_reg;
        }
        break;
    case 9:
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            break;
        if (arm_feature(env, ARM_FEATURE_STRONGARM))
            break; /* Ignore ReadBuffer access */
        switch (crm) {
        case 0: /* Cache lockdown.  */
	    switch (op1) {
	    case 0: /* L1 cache.  */
		switch (op2) {
		case 0:
		    env->cp15.c9_data = val;
		    break;
		case 1:
		    env->cp15.c9_insn = val;
		    break;
		default:
		    goto bad_reg;
		}
		break;
	    case 1: /* L2 cache.  */
		/* Ignore writes to L2 lockdown/auxiliary registers.  */
		break;
	    default:
		goto bad_reg;
	    }
	    break;
        case 1: /* TCM memory region registers.  */
            /* Not implemented.  */
            goto bad_reg;
        case 12: /* Performance monitor control */
            /* Performance monitors are implementation defined in v7,
             * but with an ARM recommended set of registers, which we
             * follow (although we don't actually implement any counters)
             */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* performance monitor control register */
                /* only the DP, X, D and E bits are writable */
                env->cp15.c9_pmcr &= ~0x39;
                env->cp15.c9_pmcr |= (val & 0x39);
                break;
            case 1: /* Count enable set register */
                val &= (1 << 31);
                env->cp15.c9_pmcnten |= val;
                break;
            case 2: /* Count enable clear */
                val &= (1 << 31);
                env->cp15.c9_pmcnten &= ~val;
                break;
            case 3: /* Overflow flag status */
                env->cp15.c9_pmovsr &= ~val;
                break;
            case 4: /* Software increment */
                /* RAZ/WI since we don't implement the software-count event */
                break;
            case 5: /* Event counter selection register */
                /* Since we don't implement any events, writing to this register
                 * is actually UNPREDICTABLE. So we choose to RAZ/WI.
                 */
                break;
            default:
                goto bad_reg;
            }
            break;
        case 13: /* Performance counters */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* Cycle count register: not implemented, so RAZ/WI */
                break;
            case 1: /* Event type select */
                env->cp15.c9_pmxevtyper = val & 0xff;
                break;
            case 2: /* Event count register */
                /* Unimplemented (we have no events), RAZ/WI */
                break;
            default:
                goto bad_reg;
            }
            break;
        case 14: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* user enable */
                env->cp15.c9_pmuserenr = val & 1;
                /* changes access rights for cp registers, so flush tbs */
                tb_flush(env);
                break;
            case 1: /* interrupt enable set */
                /* We have no event counters so only the C bit can be changed */
                val &= (1 << 31);
                env->cp15.c9_pminten |= val;
                break;
            case 2: /* interrupt enable clear */
                val &= (1 << 31);
                env->cp15.c9_pminten &= ~val;
                break;
            }
            break;
        default:
            goto bad_reg;
        }
        break;
    case 10: /* MMU TLB lockdown.  */
        /* ??? TLB lockdown not implemented.  */
        break;
    case 12: /* Reserved.  */
        goto bad_reg;
    case 13: /* Process ID.  */
        switch (op2) {
        case 0:
            /* Unlike real hardware the qemu TLB uses virtual addresses,
               not modified virtual addresses, so this causes a TLB flush.
             */
            if (env->cp15.c13_fcse != val)
              tlb_flush(env, 1);
            env->cp15.c13_fcse = val;
            break;
        case 1:
            /* This changes the ASID, so do a TLB flush.  */
            if (env->cp15.c13_context != val
                && !arm_feature(env, ARM_FEATURE_MPU))
              tlb_flush(env, 0);
            env->cp15.c13_context = val;
            break;
        default:
            goto bad_reg;
        }
        break;
    case 14: /* Reserved.  */
        goto bad_reg;
    case 15: /* Implementation specific.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            if (op2 == 0 && crm == 1) {
                if (env->cp15.c15_cpar != (val & 0x3fff)) {
                    /* Changes cp0 to cp13 behavior, so needs a TB flush.  */
                    tb_flush(env);
                    env->cp15.c15_cpar = val & 0x3fff;
                }
                break;
            }
            goto bad_reg;
        }
        if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
            switch (crm) {
            case 0:
                break;
            case 1: /* Set TI925T configuration.  */
                env->cp15.c15_ticonfig = val & 0xe7;
                env->cp15.c0_cpuid = (val & (1 << 5)) ? /* OS_TYPE bit */
                        ARM_CPUID_TI915T : ARM_CPUID_TI925T;
                break;
            case 2: /* Set I_max.  */
                env->cp15.c15_i_max = val;
                break;
            case 3: /* Set I_min.  */
                env->cp15.c15_i_min = val;
                break;
            case 4: /* Set thread-ID.  */
                env->cp15.c15_threadid = val & 0xffff;
                break;
            case 8: /* Wait-for-interrupt (deprecated).  */
                cpu_interrupt(env, CPU_INTERRUPT_HALT);
                break;
            default:
                goto bad_reg;
            }
        }
        break;
    }
    return;
bad_reg:
    /* ??? For debugging only.  Should raise illegal instruction exception.  */
    cpu_abort(env, "Unimplemented cp15 register write (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
}

uint32_t HELPER(get_cp15)(CPUState *env, uint32_t insn)
{
    int op1;
    int op2;
    int crm;

    op1 = (insn >> 21) & 7;
    op2 = (insn >> 5) & 7;
    crm = insn & 0xf;
    switch ((insn >> 16) & 0xf) {
    case 0: /* ID codes.  */
        switch (op1) {
        case 0:
            switch (crm) {
            case 0:
                switch (op2) {
                case 0: /* Device ID.  */
                    return env->cp15.c0_cpuid;
                case 1: /* Cache Type.  */
		    return env->cp15.c0_cachetype;
                case 2: /* TCM status.  */
                    return 0;
                case 3: /* TLB type register.  */
                    return 0; /* No lockable TLB entries.  */
                case 5: /* MPIDR */
                    /* The MPIDR was standardised in v7; prior to
                     * this it was implemented only in the 11MPCore.
                     * For all other pre-v7 cores it does not exist.
                     */
                    if (arm_feature(env, ARM_FEATURE_V7) ||
                        ARM_CPUID(env) == ARM_CPUID_ARM11MPCORE) {
                        int mpidr = env->cpu_index;
                        /* We don't support setting cluster ID ([8..11])
                         * so these bits always RAZ.
                         */
                        if (arm_feature(env, ARM_FEATURE_V7MP)) {
                            mpidr |= (1 << 31);
                            /* Cores which are uniprocessor (non-coherent)
                             * but still implement the MP extensions set
                             * bit 30. (For instance, A9UP.) However we do
                             * not currently model any of those cores.
                             */
                        }
                        return mpidr;
                    }
                    /* otherwise fall through to the unimplemented-reg case */
                default:
                    goto bad_reg;
                }
            case 1:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    goto bad_reg;
                return env->cp15.c0_c1[op2];
            case 2:
                if (!arm_feature(env, ARM_FEATURE_V6))
                    goto bad_reg;
                return env->cp15.c0_c2[op2];
            case 3: case 4: case 5: case 6: case 7:
                return 0;
            default:
                goto bad_reg;
            }
        case 1:
            /* These registers aren't documented on arm11 cores.  However
               Linux looks at them anyway.  */
            if (!arm_feature(env, ARM_FEATURE_V6))
                goto bad_reg;
            if (crm != 0)
                goto bad_reg;
            if (!arm_feature(env, ARM_FEATURE_V7))
                return 0;

            switch (op2) {
            case 0:
                return env->cp15.c0_ccsid[env->cp15.c0_cssel];
            case 1:
                return env->cp15.c0_clid;
            case 7:
                return 0;
            }
            goto bad_reg;
        case 2:
            if (op2 != 0 || crm != 0)
                goto bad_reg;
            return env->cp15.c0_cssel;
        default:
            goto bad_reg;
        }
    case 1: /* System configuration.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0: /* Control register.  */
            return env->cp15.c1_sys;
        case 1: /* Auxiliary control register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                return env->cp15.c1_xscaleauxcr;
            if (!arm_feature(env, ARM_FEATURE_AUXCR))
                goto bad_reg;
            switch (ARM_CPUID(env)) {
            case ARM_CPUID_ARM1026:
                return 1;
            case ARM_CPUID_ARM1136:
            case ARM_CPUID_ARM1136_R2:
            case ARM_CPUID_ARM1176:
                return 7;
            case ARM_CPUID_ARM11MPCORE:
                return 1;
            case ARM_CPUID_CORTEXA8:
                return 2;
            case ARM_CPUID_CORTEXA9:
                return 0;
            default:
                goto bad_reg;
            }
        case 2: /* Coprocessor access register.  */
            if (arm_feature(env, ARM_FEATURE_XSCALE))
                goto bad_reg;
            return env->cp15.c1_coproc;
        default:
            goto bad_reg;
        }
    case 2: /* MMU Page table control / MPU cache control.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            switch (op2) {
            case 0:
                return env->cp15.c2_data;
                break;
            case 1:
                return env->cp15.c2_insn;
                break;
            default:
                goto bad_reg;
            }
        } else {
	    switch (op2) {
	    case 0:
		return env->cp15.c2_base0;
	    case 1:
		return env->cp15.c2_base1;
	    case 2:
                return env->cp15.c2_control;
	    default:
		goto bad_reg;
	    }
	}
    case 3: /* MMU Domain access control / MPU write buffer control.  */
        return env->cp15.c3;
    case 4: /* Reserved.  */
        goto bad_reg;
    case 5: /* MMU Fault status / MPU access permission.  */
        if (arm_feature(env, ARM_FEATURE_OMAPCP))
            op2 = 0;
        switch (op2) {
        case 0:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env->cp15.c5_data);
            return env->cp15.c5_data;
        case 1:
            if (arm_feature(env, ARM_FEATURE_MPU))
                return simple_mpu_ap_bits(env->cp15.c5_data);
            return env->cp15.c5_insn;
        case 2:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            return env->cp15.c5_data;
        case 3:
            if (!arm_feature(env, ARM_FEATURE_MPU))
                goto bad_reg;
            return env->cp15.c5_insn;
        default:
            goto bad_reg;
        }
    case 6: /* MMU Fault address.  */
        if (arm_feature(env, ARM_FEATURE_MPU)) {
            if (crm >= 8)
                goto bad_reg;
            return env->cp15.c6_region[crm];
        } else {
            if (arm_feature(env, ARM_FEATURE_OMAPCP))
                op2 = 0;
	    switch (op2) {
	    case 0:
		return env->cp15.c6_data;
	    case 1:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Watchpoint Fault Adrress.  */
		    return 0; /* Not implemented.  */
		} else {
		    /* Instruction Fault Adrress.  */
		    /* Arm9 doesn't have an IFAR, but implementing it anyway
		       shouldn't do any harm.  */
		    return env->cp15.c6_insn;
		}
	    case 2:
		if (arm_feature(env, ARM_FEATURE_V6)) {
		    /* Instruction Fault Adrress.  */
		    return env->cp15.c6_insn;
		} else {
		    goto bad_reg;
		}
	    default:
		goto bad_reg;
	    }
        }
    case 7: /* Cache control.  */
        if (crm == 4 && op1 == 0 && op2 == 0) {
            return env->cp15.c7_par;
        }
        /* FIXME: Should only clear Z flag if destination is r15.  */
        env->ZF = 0;
        return 0;
    case 8: /* MMU TLB control.  */
        goto bad_reg;
    case 9:
        switch (crm) {
        case 0: /* Cache lockdown */
            switch (op1) {
            case 0: /* L1 cache.  */
                if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
                    return 0;
                }
                switch (op2) {
                case 0:
                    return env->cp15.c9_data;
                case 1:
                    return env->cp15.c9_insn;
                default:
                    goto bad_reg;
                }
            case 1: /* L2 cache */
                if (crm != 0) {
                    goto bad_reg;
                }
                /* L2 Lockdown and Auxiliary control.  */
                return 0;
            default:
                goto bad_reg;
            }
            break;
        case 12: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* performance monitor control register */
                return env->cp15.c9_pmcr;
            case 1: /* count enable set */
            case 2: /* count enable clear */
                return env->cp15.c9_pmcnten;
            case 3: /* overflow flag status */
                return env->cp15.c9_pmovsr;
            case 4: /* software increment */
            case 5: /* event counter selection register */
                return 0; /* Unimplemented, RAZ/WI */
            default:
                goto bad_reg;
            }
        case 13: /* Performance counters */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 1: /* Event type select */
                return env->cp15.c9_pmxevtyper;
            case 0: /* Cycle count register */
            case 2: /* Event count register */
                /* Unimplemented, so RAZ/WI */
                return 0;
            default:
                goto bad_reg;
            }
        case 14: /* Performance monitor control */
            if (!arm_feature(env, ARM_FEATURE_V7)) {
                goto bad_reg;
            }
            switch (op2) {
            case 0: /* user enable */
                return env->cp15.c9_pmuserenr;
            case 1: /* interrupt enable set */
            case 2: /* interrupt enable clear */
                return env->cp15.c9_pminten;
            default:
                goto bad_reg;
            }
        default:
            goto bad_reg;
        }
        break;
    case 10: /* MMU TLB lockdown.  */
        /* ??? TLB lockdown not implemented.  */
        return 0;
    case 11: /* TCM DMA control.  */
    case 12: /* Reserved.  */
        goto bad_reg;
    case 13: /* Process ID.  */
        switch (op2) {
        case 0:
            return env->cp15.c13_fcse;
        case 1:
            return env->cp15.c13_context;
        default:
            goto bad_reg;
        }
    case 14: /* Reserved.  */
        goto bad_reg;
    case 15: /* Implementation specific.  */
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            if (op2 == 0 && crm == 1)
                return env->cp15.c15_cpar;

            goto bad_reg;
        }
        if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
            switch (crm) {
            case 0:
                return 0;
            case 1: /* Read TI925T configuration.  */
                return env->cp15.c15_ticonfig;
            case 2: /* Read I_max.  */
                return env->cp15.c15_i_max;
            case 3: /* Read I_min.  */
                return env->cp15.c15_i_min;
            case 4: /* Read thread-ID.  */
                return env->cp15.c15_threadid;
            case 8: /* TI925T_status */
                return 0;
            }
            /* TODO: Peripheral port remap register:
             * On OMAP2 mcr p15, 0, rn, c15, c2, 4 sets up the interrupt
             * controller base address at $rn & ~0xfff and map size of
             * 0x200 << ($rn & 0xfff), when MMU is off.  */
            goto bad_reg;
        }
        return 0;
    }
bad_reg:
    /* ??? For debugging only.  Should raise illegal instruction exception.  */
    cpu_abort(env, "Unimplemented cp15 register read (c%d, c%d, {%d, %d})\n",
              (insn >> 16) & 0xf, crm, op1, op2);
    return 0;
}

void HELPER(set_r13_banked)(CPUState *env, uint32_t mode, uint32_t val)
{
    if ((env->uncached_cpsr & CPSR_M) == mode) {
        env->regs[13] = val;
    } else {
        env->banked_r13[bank_number(env, mode)] = val;
    }
}

uint32_t HELPER(get_r13_banked)(CPUState *env, uint32_t mode)
{
    if ((env->uncached_cpsr & CPSR_M) == mode) {
        return env->regs[13];
    } else {
        return env->banked_r13[bank_number(env, mode)];
    }
}

uint32_t HELPER(v7m_mrs)(CPUState *env, uint32_t reg)
{
    switch (reg) {
    case 0: /* APSR */
        return xpsr_read(env) & 0xf8000000;
    case 1: /* IAPSR */
        return xpsr_read(env) & 0xf80001ff;
    case 2: /* EAPSR */
        return xpsr_read(env) & 0xff00fc00;
    case 3: /* xPSR */
        return xpsr_read(env) & 0xff00fdff;
    case 5: /* IPSR */
        return xpsr_read(env) & 0x000001ff;
    case 6: /* EPSR */
        return xpsr_read(env) & 0x0700fc00;
    case 7: /* IEPSR */
        return xpsr_read(env) & 0x0700edff;
    case 8: /* MSP */
        return env->v7m.current_sp ? env->v7m.other_sp : env->regs[13];
    case 9: /* PSP */
        return env->v7m.current_sp ? env->regs[13] : env->v7m.other_sp;
    case 16: /* PRIMASK */
        return (env->uncached_cpsr & CPSR_I) != 0;
    case 17: /* BASEPRI */
    case 18: /* BASEPRI_MAX */
        return env->v7m.basepri;
    case 19: /* FAULTMASK */
        return (env->uncached_cpsr & CPSR_F) != 0;
    case 20: /* CONTROL */
        return env->v7m.control;
    default:
        /* ??? For debugging only.  */
        cpu_abort(env, "Unimplemented system register read (%d)\n", reg);
        return 0;
    }
}

void HELPER(v7m_msr)(CPUState *env, uint32_t reg, uint32_t val)
{
    switch (reg) {
    case 0: /* APSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 1: /* IAPSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 2: /* EAPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 3: /* xPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 5: /* IPSR */
        /* IPSR bits are readonly.  */
        break;
    case 6: /* EPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 7: /* IEPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 8: /* MSP */
        if (env->v7m.current_sp)
            env->v7m.other_sp = val;
        else
            env->regs[13] = val;
        break;
    case 9: /* PSP */
        if (env->v7m.current_sp)
            env->regs[13] = val;
        else
            env->v7m.other_sp = val;
        break;
    case 16: /* PRIMASK */
        if (val & 1)
            env->uncached_cpsr |= CPSR_I;
        else
            env->uncached_cpsr &= ~CPSR_I;
        break;
    case 17: /* BASEPRI */
        env->v7m.basepri = val & 0xff;
        break;
    case 18: /* BASEPRI_MAX */
        val &= 0xff;
        if (val != 0 && (val < env->v7m.basepri || env->v7m.basepri == 0))
            env->v7m.basepri = val;
        break;
    case 19: /* FAULTMASK */
        if (val & 1)
            env->uncached_cpsr |= CPSR_F;
        else
            env->uncached_cpsr &= ~CPSR_F;
        break;
    case 20: /* CONTROL */
        env->v7m.control = val & 3;
        switch_v7m_sp(env, (val & 2) != 0);
        break;
    default:
        /* ??? For debugging only.  */
        cpu_abort(env, "Unimplemented system register write (%d)\n", reg);
        return;
    }
}

void cpu_arm_set_cp_io(CPUARMState *env, int cpnum,
                ARMReadCPFunc *cp_read, ARMWriteCPFunc *cp_write,
                void *opaque)
{
    if (cpnum < 0 || cpnum > 14) {
        cpu_abort(env, "Bad coprocessor number: %i\n", cpnum);
        return;
    }

    env->cp[cpnum].cp_read = cp_read;
    env->cp[cpnum].cp_write = cp_write;
    env->cp[cpnum].opaque = opaque;
}

#endif

/* Note that signed overflow is undefined in C.  The following routines are
   careful to use unsigned types where modulo arithmetic is required.
   Failure to do so _will_ break on newer gcc.  */

/* Signed saturating arithmetic.  */

/* Perform 16-bit signed saturating addition.  */
static inline uint16_t add16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a + b;
    if (((res ^ a) & 0x8000) && !((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating addition.  */
static inline uint8_t add8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a + b;
    if (((res ^ a) & 0x80) && !((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

/* Perform 16-bit signed saturating subtraction.  */
static inline uint16_t sub16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a - b;
    if (((res ^ a) & 0x8000) && ((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating subtraction.  */
static inline uint8_t sub8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a - b;
    if (((res ^ a) & 0x80) && ((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

#define ADD16(a, b, n) RESULT(add16_sat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_sat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_sat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_sat(a, b), n, 8);
#define PFX q

#include "op_addsub.h"

/* Unsigned saturating arithmetic.  */
static inline uint16_t add16_usat(uint16_t a, uint16_t b)
{
    uint16_t res;
    res = a + b;
    if (res < a)
        res = 0xffff;
    return res;
}

static inline uint16_t sub16_usat(uint16_t a, uint16_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

static inline uint8_t add8_usat(uint8_t a, uint8_t b)
{
    uint8_t res;
    res = a + b;
    if (res < a)
        res = 0xff;
    return res;
}

static inline uint8_t sub8_usat(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

#define ADD16(a, b, n) RESULT(add16_usat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_usat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_usat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_usat(a, b), n, 8);
#define PFX uq

#include "op_addsub.h"

/* Signed modulo arithmetic.  */
#define SARITH16(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int16_t)(a) op (int32_t)(int16_t)(b); \
    RESULT(sum, n, 16); \
    if (sum >= 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SARITH8(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int8_t)(a) op (int32_t)(int8_t)(b); \
    RESULT(sum, n, 8); \
    if (sum >= 0) \
        ge |= 1 << n; \
    } while(0)


#define ADD16(a, b, n) SARITH16(a, b, n, +)
#define SUB16(a, b, n) SARITH16(a, b, n, -)
#define ADD8(a, b, n)  SARITH8(a, b, n, +)
#define SUB8(a, b, n)  SARITH8(a, b, n, -)
#define PFX s
#define ARITH_GE

#include "op_addsub.h"

/* Unsigned modulo arithmetic.  */
#define ADD16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 1) \
        ge |= 3 << (n * 2); \
    } while(0)

#define ADD8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 1) \
        ge |= 1 << n; \
    } while(0)

#define SUB16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SUB8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 0) \
        ge |= 1 << n; \
    } while(0)

#define PFX u
#define ARITH_GE

#include "op_addsub.h"

/* Halved signed arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) + (int32_t)(int16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) - (int32_t)(int16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) + (int32_t)(int8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) - (int32_t)(int8_t)(b)) >> 1, n, 8)
#define PFX sh

#include "op_addsub.h"

/* Halved unsigned arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define PFX uh

#include "op_addsub.h"

static inline uint8_t do_usad(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return b - a;
}

/* Unsigned sum of absolute byte differences.  */
uint32_t HELPER(usad8)(uint32_t a, uint32_t b)
{
    uint32_t sum;
    sum = do_usad(a, b);
    sum += do_usad(a >> 8, b >> 8);
    sum += do_usad(a >> 16, b >>16);
    sum += do_usad(a >> 24, b >> 24);
    return sum;
}

/* For ARMv6 SEL instruction.  */
uint32_t HELPER(sel_flags)(uint32_t flags, uint32_t a, uint32_t b)
{
    uint32_t mask;

    mask = 0;
    if (flags & 1)
        mask |= 0xff;
    if (flags & 2)
        mask |= 0xff00;
    if (flags & 4)
        mask |= 0xff0000;
    if (flags & 8)
        mask |= 0xff000000;
    return (a & mask) | (b & ~mask);
}

uint32_t HELPER(logicq_cc)(uint64_t val)
{
    return (val >> 32) | (val != 0);
}

/* VFP support.  We follow the convention used for VFP instrunctions:
   Single precition routines have a "s" suffix, double precision a
   "d" suffix.  */

/* Convert host exception flags to vfp form.  */
static inline int vfp_exceptbits_from_host(int host_bits)
{
    int target_bits = 0;

    if (host_bits & float_flag_invalid)
        target_bits |= 1;
    if (host_bits & float_flag_divbyzero)
        target_bits |= 2;
    if (host_bits & float_flag_overflow)
        target_bits |= 4;
    if (host_bits & (float_flag_underflow | float_flag_output_denormal))
        target_bits |= 8;
    if (host_bits & float_flag_inexact)
        target_bits |= 0x10;
    if (host_bits & float_flag_input_denormal)
        target_bits |= 0x80;
    return target_bits;
}

uint32_t HELPER(vfp_get_fpscr)(CPUState *env)
{
    int i;
    uint32_t fpscr;

    fpscr = (env->vfp.xregs[ARM_VFP_FPSCR] & 0xffc8ffff)
            | (env->vfp.vec_len << 16)
            | (env->vfp.vec_stride << 20);
    i = get_float_exception_flags(&env->vfp.fp_status);
    i |= get_float_exception_flags(&env->vfp.standard_fp_status);
    fpscr |= vfp_exceptbits_from_host(i);
    return fpscr;
}

uint32_t vfp_get_fpscr(CPUState *env)
{
    return HELPER(vfp_get_fpscr)(env);
}

/* Convert vfp exception flags to target form.  */
static inline int vfp_exceptbits_to_host(int target_bits)
{
    int host_bits = 0;

    if (target_bits & 1)
        host_bits |= float_flag_invalid;
    if (target_bits & 2)
        host_bits |= float_flag_divbyzero;
    if (target_bits & 4)
        host_bits |= float_flag_overflow;
    if (target_bits & 8)
        host_bits |= float_flag_underflow;
    if (target_bits & 0x10)
        host_bits |= float_flag_inexact;
    if (target_bits & 0x80)
        host_bits |= float_flag_input_denormal;
    return host_bits;
}

void HELPER(vfp_set_fpscr)(CPUState *env, uint32_t val)
{
    int i;
    uint32_t changed;

    changed = env->vfp.xregs[ARM_VFP_FPSCR];
    env->vfp.xregs[ARM_VFP_FPSCR] = (val & 0xffc8ffff);
    env->vfp.vec_len = (val >> 16) & 7;
    env->vfp.vec_stride = (val >> 20) & 3;

    changed ^= val;
    if (changed & (3 << 22)) {
        i = (val >> 22) & 3;
        switch (i) {
        case 0:
            i = float_round_nearest_even;
            break;
        case 1:
            i = float_round_up;
            break;
        case 2:
            i = float_round_down;
            break;
        case 3:
            i = float_round_to_zero;
            break;
        }
        set_float_rounding_mode(i, &env->vfp.fp_status);
    }
    if (changed & (1 << 24)) {
        set_flush_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
        set_flush_inputs_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
    }
    if (changed & (1 << 25))
        set_default_nan_mode((val & (1 << 25)) != 0, &env->vfp.fp_status);

    i = vfp_exceptbits_to_host(val);
    set_float_exception_flags(i, &env->vfp.fp_status);
    set_float_exception_flags(0, &env->vfp.standard_fp_status);
}

void vfp_set_fpscr(CPUState *env, uint32_t val)
{
    HELPER(vfp_set_fpscr)(env, val);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

#define VFP_BINOP(name) \
float32 VFP_HELPER(name, s)(float32 a, float32 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float32_ ## name(a, b, fpst); \
} \
float64 VFP_HELPER(name, d)(float64 a, float64 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float64_ ## name(a, b, fpst); \
}
VFP_BINOP(add)
VFP_BINOP(sub)
VFP_BINOP(mul)
VFP_BINOP(div)
#undef VFP_BINOP

float32 VFP_HELPER(neg, s)(float32 a)
{
    return float32_chs(a);
}

float64 VFP_HELPER(neg, d)(float64 a)
{
    return float64_chs(a);
}

float32 VFP_HELPER(abs, s)(float32 a)
{
    return float32_abs(a);
}

float64 VFP_HELPER(abs, d)(float64 a)
{
    return float64_abs(a);
}

float32 VFP_HELPER(sqrt, s)(float32 a, CPUState *env)
{
    return float32_sqrt(a, &env->vfp.fp_status);
}

float64 VFP_HELPER(sqrt, d)(float64 a, CPUState *env)
{
    return float64_sqrt(a, &env->vfp.fp_status);
}

/* XXX: check quiet/signaling case */
#define DO_VFP_cmp(p, type) \
void VFP_HELPER(cmp, p)(type a, type b, CPUState *env)  \
{ \
    uint32_t flags; \
    switch(type ## _compare_quiet(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
} \
void VFP_HELPER(cmpe, p)(type a, type b, CPUState *env) \
{ \
    uint32_t flags; \
    switch(type ## _compare(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
}
DO_VFP_cmp(s, float32)
DO_VFP_cmp(d, float64)
#undef DO_VFP_cmp

/* Integer to float and float to integer conversions */

#define CONV_ITOF(name, fsz, sign) \
    float##fsz HELPER(name)(uint32_t x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return sign##int32_to_##float##fsz(x, fpst); \
}

#define CONV_FTOI(name, fsz, sign, round) \
uint32_t HELPER(name)(float##fsz x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    return float##fsz##_to_##sign##int32##round(x, fpst); \
}

#define FLOAT_CONVS(name, p, fsz, sign) \
CONV_ITOF(vfp_##name##to##p, fsz, sign) \
CONV_FTOI(vfp_to##name##p, fsz, sign, ) \
CONV_FTOI(vfp_to##name##z##p, fsz, sign, _round_to_zero)

FLOAT_CONVS(si, s, 32, )
FLOAT_CONVS(si, d, 64, )
FLOAT_CONVS(ui, s, 32, u)
FLOAT_CONVS(ui, d, 64, u)

#undef CONV_ITOF
#undef CONV_FTOI
#undef FLOAT_CONVS

/* floating point conversion */
float64 VFP_HELPER(fcvtd, s)(float32 x, CPUState *env)
{
    float64 r = float32_to_float64(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float64_maybe_silence_nan(r);
}

float32 VFP_HELPER(fcvts, d)(float64 x, CPUState *env)
{
    float32 r =  float64_to_float32(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float32_maybe_silence_nan(r);
}

/* VFP3 fixed point conversion.  */
#define VFP_CONV_FIX(name, p, fsz, itype, sign) \
float##fsz HELPER(vfp_##name##to##p)(uint##fsz##_t  x, uint32_t shift, \
                                    void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    float##fsz tmp; \
    tmp = sign##int32_to_##float##fsz((itype##_t)x, fpst); \
    return float##fsz##_scalbn(tmp, -(int)shift, fpst); \
} \
uint##fsz##_t HELPER(vfp_to##name##p)(float##fsz x, uint32_t shift, \
                                       void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    float##fsz tmp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    tmp = float##fsz##_scalbn(x, shift, fpst); \
    return float##fsz##_to_##itype##_round_to_zero(tmp, fpst); \
}

VFP_CONV_FIX(sh, d, 64, int16, )
VFP_CONV_FIX(sl, d, 64, int32, )
VFP_CONV_FIX(uh, d, 64, uint16, u)
VFP_CONV_FIX(ul, d, 64, uint32, u)
VFP_CONV_FIX(sh, s, 32, int16, )
VFP_CONV_FIX(sl, s, 32, int32, )
VFP_CONV_FIX(uh, s, 32, uint16, u)
VFP_CONV_FIX(ul, s, 32, uint32, u)
#undef VFP_CONV_FIX

/* Half precision conversions.  */
static float32 do_fcvt_f16_to_f32(uint32_t a, CPUState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float32 r = float16_to_float32(make_float16(a), ieee, s);
    if (ieee) {
        return float32_maybe_silence_nan(r);
    }
    return r;
}

static uint32_t do_fcvt_f32_to_f16(float32 a, CPUState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float16 r = float32_to_float16(a, ieee, s);
    if (ieee) {
        r = float16_maybe_silence_nan(r);
    }
    return float16_val(r);
}

float32 HELPER(neon_fcvt_f16_to_f32)(uint32_t a, CPUState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.standard_fp_status);
}

uint32_t HELPER(neon_fcvt_f32_to_f16)(float32 a, CPUState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.standard_fp_status);
}

float32 HELPER(vfp_fcvt_f16_to_f32)(uint32_t a, CPUState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.fp_status);
}

uint32_t HELPER(vfp_fcvt_f32_to_f16)(float32 a, CPUState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.fp_status);
}

#define float32_two make_float32(0x40000000)
#define float32_three make_float32(0x40400000)
#define float32_one_point_five make_float32(0x3fc00000)

float32 HELPER(recps_f32)(float32 a, float32 b, CPUState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_two;
    }
    return float32_sub(float32_two, float32_mul(a, b, s), s);
}

float32 HELPER(rsqrts_f32)(float32 a, float32 b, CPUState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    float32 product;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_one_point_five;
    }
    product = float32_mul(a, b, s);
    return float32_div(float32_sub(float32_three, product, s), float32_two, s);
}

/* NEON helpers.  */

/* Constants 256 and 512 are used in some helpers; we avoid relying on
 * int->float conversions at run-time.  */
#define float64_256 make_float64(0x4070000000000000LL)
#define float64_512 make_float64(0x4080000000000000LL)

/* The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM.
 */
static float64 recip_estimate(float64 a, CPUState *env)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = env->vfp.standard_fp_status;
    float_status *s = &dummy_status;
    /* q = (int)(a * 512.0) */
    float64 q = float64_mul(float64_512, a, s);
    int64_t q_int = float64_to_int64_round_to_zero(q, s);

    /* r = 1.0 / (((double)q + 0.5) / 512.0) */
    q = int64_to_float64(q_int, s);
    q = float64_add(q, float64_half, s);
    q = float64_div(q, float64_512, s);
    q = float64_div(float64_one, q, s);

    /* s = (int)(256.0 * r + 0.5) */
    q = float64_mul(q, float64_256, s);
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0 */
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

float32 HELPER(recpe_f32)(float32 a, CPUState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    float64 f64;
    uint32_t val32 = float32_val(a);

    int result_exp;
    int a_exp = (val32  & 0x7f800000) >> 23;
    int sign = val32 & 0x80000000;

    if (float32_is_any_nan(a)) {
        if (float32_is_signaling_nan(a)) {
            float_raise(float_flag_invalid, s);
        }
        return float32_default_nan;
    } else if (float32_is_infinity(a)) {
        return float32_set_sign(float32_zero, float32_is_neg(a));
    } else if (float32_is_zero_or_denormal(a)) {
        if (!float32_is_zero(a)) {
            float_raise(float_flag_input_denormal, s);
        }
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(a));
    } else if (a_exp >= 253) {
        float_raise(float_flag_underflow, s);
        return float32_set_sign(float32_zero, float32_is_neg(a));
    }

    f64 = make_float64((0x3feULL << 52)
                       | ((int64_t)(val32 & 0x7fffff) << 29));

    result_exp = 253 - a_exp;

    f64 = recip_estimate(f64, env);

    val32 = sign
        | ((result_exp & 0xff) << 23)
        | ((float64_val(f64) >> 29) & 0x7fffff);
    return make_float32(val32);
}

/* The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM.
 */
static float64 recip_sqrt_estimate(float64 a, CPUState *env)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = env->vfp.standard_fp_status;
    float_status *s = &dummy_status;
    float64 q;
    int64_t q_int;

    if (float64_lt(a, float64_half, s)) {
        /* range 0.25 <= a < 0.5 */

        /* a in units of 1/512 rounded down */
        /* q0 = (int)(a * 512.0);  */
        q = float64_mul(float64_512, a, s);
        q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 / sqrt(((double)q0 + 0.5) / 512.0);  */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_512, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    } else {
        /* range 0.5 <= a < 1.0 */

        /* a in units of 1/256 rounded down */
        /* q1 = (int)(a * 256.0); */
        q = float64_mul(float64_256, a, s);
        int64_t q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 /sqrt(((double)q1 + 0.5) / 256); */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_256, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    }
    /* r in units of 1/256 rounded to nearest */
    /* s = (int)(256.0 * r + 0.5); */

    q = float64_mul(q, float64_256,s );
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0;*/
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

float32 HELPER(rsqrte_f32)(float32 a, CPUState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    int result_exp;
    float64 f64;
    uint32_t val;
    uint64_t val64;

    val = float32_val(a);

    if (float32_is_any_nan(a)) {
        if (float32_is_signaling_nan(a)) {
            float_raise(float_flag_invalid, s);
        }
        return float32_default_nan;
    } else if (float32_is_zero_or_denormal(a)) {
        if (!float32_is_zero(a)) {
            float_raise(float_flag_input_denormal, s);
        }
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(a));
    } else if (float32_is_neg(a)) {
        float_raise(float_flag_invalid, s);
        return float32_default_nan;
    } else if (float32_is_infinity(a)) {
        return float32_zero;
    }

    /* Normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */
    if ((val & 0x800000) == 0) {
        f64 = make_float64(((uint64_t)(val & 0x80000000) << 32)
                           | (0x3feULL << 52)
                           | ((uint64_t)(val & 0x7fffff) << 29));
    } else {
        f64 = make_float64(((uint64_t)(val & 0x80000000) << 32)
                           | (0x3fdULL << 52)
                           | ((uint64_t)(val & 0x7fffff) << 29));
    }

    result_exp = (380 - ((val & 0x7f800000) >> 23)) / 2;

    f64 = recip_sqrt_estimate(f64, env);

    val64 = float64_val(f64);

    val = ((result_exp & 0xff) << 23)
        | ((val64 >> 29)  & 0x7fffff);
    return make_float32(val);
}

uint32_t HELPER(recpe_u32)(uint32_t a, CPUState *env)
{
    float64 f64;

    if ((a & 0x80000000) == 0) {
        return 0xffffffff;
    }

    f64 = make_float64((0x3feULL << 52)
                       | ((int64_t)(a & 0x7fffffff) << 21));

    f64 = recip_estimate (f64, env);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

uint32_t HELPER(rsqrte_u32)(uint32_t a, CPUState *env)
{
    float64 f64;

    if ((a & 0xc0000000) == 0) {
        return 0xffffffff;
    }

    if (a & 0x80000000) {
        f64 = make_float64((0x3feULL << 52)
                           | ((uint64_t)(a & 0x7fffffff) << 21));
    } else { /* bits 31-30 == '01' */
        f64 = make_float64((0x3fdULL << 52)
                           | ((uint64_t)(a & 0x3fffffff) << 22));
    }

    f64 = recip_sqrt_estimate(f64, env);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

/* VFPv4 fused multiply-accumulate */
float32 VFP_HELPER(muladd, s)(float32 a, float32 b, float32 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float32_muladd(a, b, c, 0, fpst);
}

float64 VFP_HELPER(muladd, d)(float64 a, float64 b, float64 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float64_muladd(a, b, c, 0, fpst);
}

void HELPER(set_teecr)(CPUState *env, uint32_t val)
{
    val &= 1;
    if (env->teecr != val) {
        env->teecr = val;
        tb_flush(env);
    }
}

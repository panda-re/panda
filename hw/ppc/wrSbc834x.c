/* ABOUT:
 * Adapted from: https://github.com/cillianodonnell/couverture_qemu/blob/patches/hw/ppc/wrSbc834x.c
 * Some functionality specific to couverture-qemu removed
 * Machine initialization updated for PANDA's QEMU version
 */

/* PowerPC microcontroller family: MPC83xx (PowerQUICC II Pro)
 * The CPU core is an e300 (its architecture is based on MPC603e)
 */

/* PowerPC board: WindRiver SBC8349E/47E
 * http://www.takefive.com/windsurf/techpubs/hwTools/referenceDesigns/
       ERG-00328-001.pdf
 */

// TODO: additions
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/hw_accel.h"

// TODO: Known good
#include "hw/hw.h"
#include "hw/ppc/ppc.h"
#include "hw/isa/isa.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "exec/address-spaces.h"
#include "kvm_ppc.h"
#include "elf.h"

// TODO: Seems OK
#include "hw/i386/pc.h"
#include "qemu-common.h"
#include "exec/memory.h"
#include "hw/net/fsl_etsec/etsec.h"
#include "hw/char/serial.h"

// TODO: new
#include "hw/intc/ipic.h"
#include "wrSbc834x_mm.h"

// TODO: questionable
// Specific to COUVERTURE QEMU
//#include "hw/hostfs.h"
//#include "qemu-plugin.h"
//#include "gnat-bus.h"
//#include "qemu-traces.h"

#define e300_VECTOR_MASK  0x000fffff
#define e300_RESET_VECTOR 0x00000100

#define CPU_NAME "MPC83xx"

#define CPU_MODEL "MPC8349E"
#define MAX_CPUS 1
#define MAX_ETSEC_CONTROLLERS 2

#define DTC_LOAD_PAD               0x500000
#define DTC_PAD_MASK               0xFFFFF

#define KERNEL_LOAD_ADDR 0
#define INITRD_LOAD_ADDR 0x01800000

#define PARAMS_ADDR     (CCSBAR_BASE + 0x80000)
#define PARAMS_SIZE     (0x01000)
//#define QTRACE_START    (CCSBAR_BASE + 0x81000)
//#define QTRACE_SIZE     (0x01000)
//#define HOSTFS_START    (CCSBAR_BASE + 0x82000)

/* #define DEBUG_MPC83XX */
#ifdef DEBUG_MPC83XX
    /* set it to 1 to print configuration changes */
    #define DEBUG_CONFIG            1
    /* set it to 1 to print read/write of registers */
    #define DEBUG_RW                1
    /* set it to 1 to print warnings on read/write of registers */
    #define DEBUG_RW_ERROR          1
    /* set it to 1 to print not implemented requests */
    #define DEBUG_NOT_IMPLEMENTED   1
#else
    #define DEBUG_CONFIG            0
    #define DEBUG_RW                0
    #define DEBUG_RW_ERROR          0
    #define DEBUG_NOT_IMPLEMENTED   0
#endif

#define eprintf(fmt, args...) { \
    fprintf(stderr, CPU_NAME ": " fmt "\n", ## args); \
    abort(); \
}
#define not_implemented0(fmt, args...) \
    fprintf(stderr, CPU_NAME ": " fmt ": not implemented\n", ## args)
#define not_implemented_register0(offset) \
    do { \
        int i = 0; \
        do { \
            if (offset >= regdescs[i].saddr && offset <= regdescs[i].eaddr) { \
                fprintf(stderr, \
                   CPU_NAME ": register 0x%08x is not implemented - %s\n", \
                   offset, regdescs[i].descr); \
            } \
            i++; \
        } while (regdescs[i].descr); \
    } while (0)
#ifdef DEBUG_MPC83XX
    #define dprintf0(fmt, args...) fprintf(stderr, fmt, ## args)
    #define not_implemented(fmt, args...) \
        if (DEBUG_NOT_IMPLEMENTED) { \
            not_implemented0(fmt, ## args); \
        }
    #define not_implemented_register(offset) \
        if (DEBUG_NOT_IMPLEMENTED) { \
            not_implemented_register0(offset); \
        }
#else
    #define dprintf0(fmt, args...) \
        do {} while (0)
    #define not_implemented(fmt, args...) \
        if (DEBUG_NOT_IMPLEMENTED) { \
            static int once; \
            if (!once) { \
                once = 1; \
                not_implemented0(fmt, ## args); \
            } \
        }
    #define not_implemented_register(offset) \
        if (DEBUG_NOT_IMPLEMENTED) { \
            static int once; \
            if (!once) { \
                once = 1; \
                not_implemented_register0(offset); \
            } \
        }
#endif
#define dprintf(fmt, args...) dprintf0(CPU_NAME ": " fmt, ## args)

/* memory mapped registers (IMMR) */
#define IMMR_SIZE 0x40000
/* timebase enable ??? unused */
#define SPCR_OFFSET 0x110
#define SPCR_TBEN_BIT (1 << (31 - 9))
/* software reset */
#define RESET_MEM_SIZE 255
#define RESET_OFFSET   0x0900
#define RPR_OFFSET  0x18
#define RPR_RSTE_VALUE 0x52535445
#define RCR_OFFSET  0x1C
#define RCR_SWxR_BITS 3
#define RCER_OFFSET 0x20
#define RCER_CRE_BIT  1

/* memory mapped registers handled by other modules */
#define IPIC_OFFSET    0x0700
#define SERIAL0_OFFSET 0x4500
#define SERIAL1_OFFSET 0x4600
#define ETSEC1_BASE        0x24000


#define CCSBAR_BASE  0xff400000

#if 0
typedef struct mpc83xx_config {
    uint32_t    ccsr_init_addr;
    const char *cpu_model;
} mpc83xx_config;
#endif

typedef struct ResetData {
    PowerPCCPU *cpu;
    uint32_t    entry;          /* save kernel entry in case of reset */
} ResetData;

static MemoryRegion *ccsr_space;
static uint64_t      ccsr_addr;

#if 0
/* THE object */
typedef struct {

    /* internal storage */
    CPUState *cpu ;
    int       immr_index ;
    hwaddr    immr_base ;

    /* registers */
    uint32_t immrbar;
    uint32_t spcr;
    uint32_t rcer;

} MPC83xxState;
#endif

#if 0
static mpc83xx_config sbc834x_config = {
    .ccsr_init_addr = 0xff400000,
    .cpu_model      = CPU_MODEL,
};
#endif

static uint64_t mpc83xx_immr_read(void *state, hwaddr address, unsigned size) {
    int          offset;
    uint32_t     value = 0;

    offset = address & 0xfffff;
    if (DEBUG_RW) {
        dprintf("%d-bits read from register 0x%05X address 0x%x\n",
                size << 3, offset, address);
    }
    switch (offset) {
    default:
        not_implemented_register(offset);
    }

    return value;
}

static void mpc83xx_immr_write(void *state, hwaddr address, uint64_t value,
                               unsigned size) {
    int          offset;

    offset = address & 0xfffff;
    if (DEBUG_RW) {
        dprintf("%d-bits write 0x%08X to register 0x%05X\n",
                size << 3, value, offset);
    }
    switch (offset) {
    default:
        not_implemented_register(offset);
    }
}

static const MemoryRegionOps mpc83xx_ops = {
    .write = mpc83xx_immr_write,
    .read  = mpc83xx_immr_read,
    .endianness = DEVICE_BIG_ENDIAN,
};

static void main_cpu_reset(void *opaque)
{
    ResetData    *s   = (ResetData *) opaque;
    PowerPCCPU   *cpu = s->cpu;
    CPUArchState *env = &cpu->env;

    cpu_reset(CPU(cpu));

    env->nip = s->entry;
}

typedef struct {

   /* board mapping */
   MemoryRegion mem;

   /* registers */
   uint32_t rcwlr;
   uint32_t rcwhr;
   uint32_t rsr;
   uint32_t rmr;
   uint32_t rpr;
   uint32_t rcr;
   uint32_t rcer;
} ResetState;

static uint64_t mpc83xx_reset_read(void *state, hwaddr address,
                                  unsigned size) {
    ResetState *s = state;
    int offset;
    uint32_t value = 0;

    offset = address & 0xfffff;
    if (DEBUG_RW) {
        dprintf("%d-bits read from register 0x%05X address 0x%x\n",
                size << 3, offset, 0x900 + offset);
    }
    switch (offset) {
    case RCER_OFFSET:
        value = s->rcer;
        break;
    default:
        not_implemented_register(offset);
    }

    return value;
}

static void mpc83xx_reset_write(void *state, hwaddr address,
                                uint64_t value, unsigned size) {
    ResetState *s = state;
    int offset;

    offset = address & 0xfffff;
    if (DEBUG_RW)
        dprintf("%d-bits write 0x%08X to register 0x%05X\n",
                size << 3, value, 0x900+offset);
    switch (offset) {
    case RPR_OFFSET:
        if (value == RPR_RSTE_VALUE) {
            dprintf("disable reset protection\n");
            /* disable reset protection */
            s->rcer = RCER_CRE_BIT;
        }
        break;
    case RCR_OFFSET:
        if (s->rcer && value & RCR_SWxR_BITS) {
            dprintf("software reset\n");
            qemu_system_reset_request();
        }
        break;
    case RCER_OFFSET:
        if (value & RCER_CRE_BIT) {
            /* enable reset protection */
            s->rcer = 0;
        }
        break;
    default:
        not_implemented_register(offset);
    }
}

static const MemoryRegionOps reset_ops = {
    .write = mpc83xx_reset_write,
    .read  = mpc83xx_reset_read,
    .endianness = DEVICE_BIG_ENDIAN,
};

// Specific to COUVERTURE QEMU

/*
static void write_qtrace(void *opaque, hwaddr addr, uint64_t value,
                         unsigned size)
{
    switch (addr & 0xfff) {
    case 0x00:
        trace_special(TRACE_SPECIAL_LOADADDR, value);
        break;
    default:
#ifdef DEBUG_MPC83XX
        printf("%s: writing non implemented register 0x%8x\n", __func__,
               QTRACE_START + addr);
#endif
        break;
    }
}
*/

// Specific to COUVERTURE QEMU

/*
static const MemoryRegionOps qtrace_ops = {
    .write = write_qtrace,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};
*/

static void reset_reset(void *state)
{
   ResetState *s = state;

   dprintf("reset reset\n");
   memset(&s->rcwlr, 0, sizeof(uint32_t));
   memset(&s->rcwhr, 0, sizeof(uint32_t));
   memset(&s->rsr, 0, sizeof(uint32_t));
   memset(&s->rmr, 0, sizeof(uint32_t));
   memset(&s->rpr, 0, sizeof(uint32_t));
   memset(&s->rcr, 0, sizeof(uint32_t));
   memset(&s->rcer, 0, sizeof(uint32_t));
}

static void reset_init(MemoryRegion *address_space,
                       hwaddr base_addr)
{
    ResetState *s = NULL;

    if (DEBUG_CONFIG) {
        dprintf("mapped at address 0x%08x\n", (uint32_t)base_addr);
    }

    /* instantiate the object and intiialize it to 0 */
    s = g_malloc0(sizeof(ResetState));
    memory_region_init_io(&s->mem, NULL, &reset_ops, s, "reset", RESET_MEM_SIZE);
    memory_region_add_subregion(address_space, base_addr, &s->mem);

    /* initialzie registers with their default values */
    reset_reset(s);
}

static void generic_init(MachineState *args,
                         const target_ulong   immr_base,
                         const uint32_t       cpu_freq)
{
    PowerPCCPU   *cpu;
    CPUPPCState  *env = NULL;
#if 0
    clk_setup_cb  clock;
    RTCState     *rtc;
    ISADevice    *pit;
#endif
    ResetData    *reset_info;
    SerialState  *serial0;
    SerialState  *serial1;
    qemu_irq     *irqs;
    qemu_irq     *devirqs;
    MemoryRegion *ram     = g_new(MemoryRegion, 1);
    MemoryRegion *immr    = g_new(MemoryRegion, 1);
    MemoryRegion *params  = g_new(MemoryRegion, 1);
    //MemoryRegion *qtrace  = g_new(MemoryRegion, 1);
    int32_t       kernel_size;
    uint64_t      kernel_pentry, kernel_lowaddr;
    target_ulong  dt_base = 0;
    int           i;

    /* initialize CPU */
    if (args->cpu_model == NULL) {
        args->cpu_model = "MPC8349";
    }

    dprintf("initialization with CPU %s\n", cpu_model);

    /* initialize CPU */
    cpu = cpu_ppc_init(args->cpu_model);
    if (cpu == NULL) {
        eprintf("unable to find CPU %s\n", args->cpu_model);
    }

    env = &cpu->env;

    /* TODO: check core inputs */
    if (PPC_INPUT(env) != PPC_FLAGS_INPUT_6xx) {
        eprintf("only 6xx bus is supported on " CPU_NAME " microcontroller");
    }

    /* set time-base frequency to 66 Mhz */
    /* should be controlled by M66EN to switch between 33 and 66 */
    cpu_ppc_tb_init(env, cpu_freq);

    /* configure reset */
    reset_info = g_malloc0(sizeof(ResetData));
    reset_info->cpu = cpu;
    qemu_register_reset(main_cpu_reset, reset_info);

    reset_info->entry = 0x0000010000UL;

    /* allocate RAM */
    memory_region_init_ram(ram, NULL, "sbc834x.ram", ram_size,
                           &error_abort);
    memory_region_add_subregion(get_system_memory(), 0x0, ram);

    ccsr_addr = immr_base;

    /* Configuration, Control, and Status Registers */
    ccsr_space = g_new(MemoryRegion, 1);
    memory_region_init(ccsr_space, NULL, "CCSR_space", 0x100000);
    memory_region_add_subregion(get_system_memory(), ccsr_addr, ccsr_space);

    memory_region_init_io(immr, NULL, &mpc83xx_ops, env, "IMMR", 0x24000);
    memory_region_add_subregion(ccsr_space, 0, immr);

#if 0
    /* register ISA IO space */
    /* TODO: check ISA, 1 MB ? Why needed ? */
    isa_mmio_init(0xff500000, 0x100000);
#endif

    /* initialize the reset registers */
    reset_init(ccsr_space, RESET_OFFSET);

    /* initialize interrupt controller */
    irqs = g_malloc0(sizeof(qemu_irq) * IPIC_OUTPUT_SIZE);
    /* TODO: change irqs pins to e300 ones */
    irqs[IPIC_OUTPUT_INT] = env->irq_inputs[PPC6xx_INPUT_INT];
    irqs[IPIC_OUTPUT_SMI] = env->irq_inputs[PPC6xx_INPUT_SMI];
    irqs[IPIC_OUTPUT_MCP] = env->irq_inputs[PPC6xx_INPUT_MCP];
    devirqs = ipic_init(ccsr_space, IPIC_OFFSET, irqs);
    if (devirqs == NULL) {
        eprintf("cannot initialize IPIC");
    }
#if 0
    /* initialize periodic interval timer */
    /* TODO: check PIT parameters */
    pit = pit_init(0x40, 65);

    /* initialize real time clock */
    /* TODO: check RTC parameters */
    rtc = rtc_init(0x70, devirqs[64], 2000);
#endif

    /* initialize serial lines */
    if (serial_hds[0] != NULL) {
        serial0 = serial_mm_init(ccsr_space, SERIAL0_OFFSET, 0, devirqs[9],
                                 9600, serial_hds[0], DEVICE_BIG_ENDIAN);
        if (serial0 == NULL) {
            eprintf("cannot initialize first serial line");
        }
    }
    if (serial_hds[1] != NULL) {
        serial1 = serial_mm_init(ccsr_space, SERIAL1_OFFSET, 0, devirqs[10],
                                 9600, serial_hds[1], DEVICE_BIG_ENDIAN);
        if (serial1 == NULL) {
            eprintf("cannot initialize second serial line");
        }
    }

    for (i = 0; i < nb_nics; i++) {
        etsec_create(ETSEC1_BASE + 0x1000 * i, ccsr_space,
                     &nd_table[i],
                     devirqs[32 + i * 3],
                     devirqs[33 + i * 3],
                     devirqs[34 + i * 3]);
    }

    if (args->kernel_filename == NULL) {
        eprintf("boot from device not currently supported");
    }

    /* load kernel */
    dprintf("load %s\n", args->kernel_filename);
    kernel_size = load_elf(args->kernel_filename, NULL, NULL, &kernel_pentry,
                            &kernel_lowaddr, NULL, 1, PPC_ELF_MACHINE, 0, 0);
    if (kernel_size < 0) {
        eprintf("cannot load kernel '%s'", args->kernel_filename);
    }

    dt_base = (kernel_size + DTC_LOAD_PAD) & ~DTC_PAD_MASK;

    cpu_synchronize_state(CPU(cpu));

    /* Set initial guest state. */
    env->gpr[1]       = kernel_lowaddr + 4 * 1024 * 1024; /* FIXME: sp? */
    env->gpr[3]       = dt_base;
    env->nip          = kernel_pentry; /* FIXME: entry? */
    reset_info->entry = kernel_pentry;

#if 0
    /* load initrd */
    if (initrd_filename) {
        initrd_base = INITRD_LOAD_ADDR;
        initrd_size = load_image_targphys(initrd_filename, initrd_base,
                                          ram_size - initrd_base);
        if (initrd_size < 0) {
            eprintf("cannot load initial ram disk '%s'", initrd_filename);
        }
    } else {
        initrd_base = 0;
        initrd_size = 0;
    }
#endif

    /* Set params.  */
    memory_region_init_ram(params, NULL, "ppc83xx.params", PARAMS_SIZE,
                           &error_abort);
    memory_region_add_subregion(get_system_memory(), PARAMS_ADDR, params);
    vmstate_register_ram_global(params);

    if (args->kernel_cmdline) {
        cpu_physical_memory_write(PARAMS_ADDR, args->kernel_cmdline,
                                  strlen(args->kernel_cmdline) + 1);
    } else {
        stb_phys(CPU(env)->as, PARAMS_ADDR, 0);
    }

    /* Set read-only after writing command line */
    memory_region_set_readonly(params, true);

    // Specific to COUVERTURE QEMU
    /* Qtrace*/
    //memory_region_init_io(qtrace, NULL, &qtrace_ops, env,
    //                      "Exec-traces", QTRACE_SIZE);
    //memory_region_add_subregion(get_system_memory(), QTRACE_START, qtrace);

    // Specific to COUVERTURE QEMU
    /* HostFS */
    //hostfs_create(HOSTFS_START, get_system_memory());

    // Specific to COUVERTURE QEMU
    /* Initialize plug-ins */
    //plugin_init(devirqs, 94);
    //plugin_device_init();

    // TODO: what is this for?
    /* Initialize the GnatBus Master */
    //gnatbus_master_init(devirqs, 94);
    //gnatbus_device_init();

    /* TODO: append command line parameters
     * see linux/arch/powerpc/kernel/prom.c (variable cmd_line) */

    /* start kernel */
    env->nip = kernel_pentry; /* instruction pointer */
    dprintf("start kernel at 0x%08X\n", s->nip);

    /* register functions to suspend/resume the current state */
    /* TODO: functions to save/load VM */
    /* register_savevm(DEVICE, 0, VERSION, mpc83xx_save, mpc83xx_load, s); */
}

#define BOARD_NAME "wrsbc834x_vxworks"
#define BOARD_DESC "WindRiver SBC834x board"

static void sbc834x_init(MachineState *args)
{
    generic_init(args,
                 0xff400000 /* IMMR_BASE */,
                 66000000 /* Freq */);
}

/*
static QEMUMachine sbc834x_machine = {
    .name = "wrsbc834x_vxworks",
    .desc = "WindRiver SBC834x board",
    .init = sbc834x_init,
    .max_cpus = MAX_CPUS
};

static void mpc8321e_init(MachineState *args)
{
    generic_init(args,
                 0xf0000000 // IMMR_BASE,
                 33250000 // Freq );
}

static QEMUMachine mpc8321e_machine = {
    .name = "MPC8321e",
    .desc = "MPC8321e",
    .init = mpc8321e_init,
    .max_cpus = MAX_CPUS
};

static void mpc83xx_machine_init(void)
{
    qemu_register_machine(&sbc834x_machine);
    qemu_register_machine(&mpc8321e_machine);
}

machine_init(mpc83xx_machine_init);
*/

static void sbc834x_machine_init(MachineClass *mc) {
    mc->desc = "WindRiver SBC834x board";
    mc->init = sbc834x_init;
    mc->max_cpus = MAX_CPUS;
}

DEFINE_MACHINE("wrsbc834x_vxworks", sbc834x_machine_init);
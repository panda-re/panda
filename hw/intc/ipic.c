// Imported from: https://github.com/cillianodonnell/couverture_qemu/blob/patches/hw/intc/ipic.c
// Modified for PANDA's QEMU version

/* IPIC emulation
 * interrupt controller of the MPC8260 (PowerQUICC II)
 *
 * In datasheet, bit 0 is the most significant.
 * To make it clear in the code, constants are defined by using (31 - x).
 */


#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "hw/intc/ipic.h"

/* #define DEBUG_IPIC */
#ifdef DEBUG_IPIC
    /* set it to print IRQs changes (input/output) */
    #define DEBUG_IRQ               0
    #define DEBUG_IRQ_SET           1
    /* set it to print masked/unmaked IRQs */
    #define DEBUG_MASK              0
    #define DEBUG_UNMASK            1
    /* set it to print configuration changes */
    #define DEBUG_CONFIG            0
    /* set it to print read/write of registers */
    #define DEBUG_RW                1
    #define DEBUG_RW_SIVCR          1
    #define DEBUG_RW_SIMSR          1
    /* set it to print warnings on read/write of registers */
    #define DEBUG_RW_ERROR          0
    /* set it to print not implemented requests */
    #define DEBUG_NOT_IMPLEMENTED   1
    #define DEBUG_TRIGGER           1
#else
    #define DEBUG_IRQ               0
    #define DEBUG_IRQ_SET           0
    #define DEBUG_MASK              0
    #define DEBUG_UNMASK            0
    #define DEBUG_CONFIG            0
    #define DEBUG_RW                0
    #define DEBUG_RW_SIVCR          0
    #define DEBUG_RW_SIMSR          0
    #define DEBUG_RW_ERROR          0
    #define DEBUG_NOT_IMPLEMENTED   0
    #define DEBUG_TRIGGER           0
#endif

#define DEBUG_RW_REG(offset) ( \
    (DEBUG_RW && \
     (offset != IPIC_SIVCR && \
      offset != IPIC_SIMSR_L && \
      offset != IPIC_SIMSR_H)) || \
    (DEBUG_RW_SIVCR && \
     (offset == IPIC_SIVCR)) || \
    (DEBUG_RW_SIMSR && \
     (offset == IPIC_SIMSR_L || offset == IPIC_SIMSR_H)))

#define eprintf(fmt, args...) fprintf(stderr, "IPIC: " fmt "\n", ## args)
#define not_implemented0(fmt, args...) { \
        if (DEBUG_NOT_IMPLEMENTED) { \
            eprintf(fmt ": not implemented\n", ## args); \
        } \
    }
#ifdef DEBUG_IPIC
    #define dprintf0(fmt, args...) fprintf(stderr, fmt, ## args)
    #define not_implemented(fmt, args...) not_implemented0(fmt, ## args)
#else
    #define dprintf0(fmt, args...) do {} while (0)
    #define not_implemented(fmt, args...) { \
        static int once; \
        if (!once) { \
            once = 1; not_implemented0(fmt, ## args); \
        } \
    }
#endif
#define dprintf(fmt, args...) dprintf0("IPIC: " fmt, ## args)

/* version of the saved state file */
#define IPIC_VERSION 0

#define IPIC_MEM_SIZE 255

typedef enum {
    IPIC_READ  = 1 << 0,
    IPIC_WRITE = 1 << 1
} IPICDirection;

#define IPIC_IO_STR(direction) ( \
    direction == IPIC_READ ? "read from" : "write to" \
)

enum ipic_reg_offsets {
    IPIC_SICFR   , /* 0x00 >> 2 */
    IPIC_SIVCR   , /* 0x04 >> 2 */
    IPIC_SIPNR_H , /* 0x08 >> 2 */
    IPIC_SIPNR_L , /* 0x0C >> 2 */
    IPIC_SIPRR_A , /* 0x10 >> 2 */
    IPIC_SIPRR_B , /* 0x14 >> 2 */
    IPIC_SIPRR_C , /* 0x18 >> 2 */
    IPIC_SIPRR_D , /* 0x1C >> 2 */
    IPIC_SIMSR_H , /* 0x20 >> 2 */
    IPIC_SIMSR_L , /* 0x24 >> 2 */
    IPIC_SICNR   , /* 0x28 >> 2 */
    IPIC_SEPNR   , /* 0x2C >> 2 */
    IPIC_SMPRR_A , /* 0x30 >> 2 */
    IPIC_SMPRR_B , /* 0x34 >> 2 */
    IPIC_SEMSR   , /* 0x38 >> 2 */
    IPIC_SECNR   , /* 0x3C >> 2 */
    IPIC_SERSR   , /* 0x40 >> 2 */
    IPIC_SERMR   , /* 0x44 >> 2 */
    IPIC_SERCR   , /* 0x48 >> 2 */
    IPIC_RESERVED, /* 0x4C >> 2 */
    IPIC_SIFCR_H , /* 0x50 >> 2 */
    IPIC_SIFCR_L , /* 0x54 >> 2 */
    IPIC_SEFCR   , /* 0x58 >> 2 */
    IPIC_SERFR   , /* 0x5C >> 2 */
    IPIC_SCVCR   , /* 0x60 >> 2 */
    IPIC_SMVCR   , /* 0x64 >> 2 */
    IPIC_REGS_SIZE
};

static const uint8_t ipic_reg_rw[] = {
    IPIC_READ | IPIC_WRITE, /* SICFR    */
    IPIC_READ             , /* SIVCR    */
    IPIC_READ             , /* SIPNR_H  */
    IPIC_READ             , /* SIPNR_L  */
    IPIC_READ | IPIC_WRITE, /* SIPRR_A  */
    IPIC_READ | IPIC_WRITE, /* SIPRR_B  */
    IPIC_READ | IPIC_WRITE, /* SIPRR_C  */
    IPIC_READ | IPIC_WRITE, /* SIPRR_D  */
    IPIC_READ | IPIC_WRITE, /* SIMSR_H  */
    IPIC_READ | IPIC_WRITE, /* SIMSR_L  */
    IPIC_READ | IPIC_WRITE, /* SICNR    */
    IPIC_READ | IPIC_WRITE, /* SEPNR    */
    IPIC_READ | IPIC_WRITE, /* SMPRR_A  */
    IPIC_READ | IPIC_WRITE, /* SMPRR_B  */
    IPIC_READ | IPIC_WRITE, /* SEMSR    */
    IPIC_READ | IPIC_WRITE, /* SECNR    */
    IPIC_READ | IPIC_WRITE, /* SERSR    */
    IPIC_READ | IPIC_WRITE, /* SERMR    */
    IPIC_READ | IPIC_WRITE, /* SERCR    */
              0           , /* reserved */
    IPIC_READ | IPIC_WRITE, /* SIFCR_H  */
    IPIC_READ | IPIC_WRITE, /* SIFCR_L  */
    IPIC_READ | IPIC_WRITE, /* SEFCR    */
    IPIC_READ | IPIC_WRITE, /* SERFR    */
    IPIC_READ             , /* SCVCR    */
    IPIC_READ               /* SMVCR    */
};

#ifdef DEBUG_IPIC
static const char *ipic_reg_name[] = {
    "SICFR",
    "SIVCR",
    "SIPNR_H",
    "SIPNR_L",
    "SIPRR_A",
    "SIPRR_B",
    "SIPRR_C",
    "SIPRR_D",
    "SIMSR_H",
    "SIMSR_L",
    "SICNR",
    "SEPNR",
    "SMPRR_A",
    "SMPRR_B",
    "SEMSR",
    "SECNR",
    "SERSR",
    "SERMR",
    "SERCR",
    "reserved (4C)",
    "SIFCR_H",
    "SIFCR_L",
    "SEFCR",
    "SERFR",
    "SCVCR",
    "SMVCR"
};
#endif

static const uint32_t ipic_reg_mask[] = {
    0x7F690300, /* SICFR    */
    0xFC00007F, /* SIVCR    */
    0xFF0000E7, /* SIPNR_H  */
    0xFFFF8C30, /* SIPNR_L  */
    0xFFF0FFF0, /* SIPRR_A  */
    0xFFF0FFF0, /* SIPRR_B  */
    0xFFF0FFF0, /* SIPRR_C  */
    0xFFF0FFF0, /* SIPRR_D  */
    0xFF0000E7, /* SIMSR_H  */
    0xFFFF8C30, /* SIMSR_L  */
    0xF00000F0, /* SICNR    */
    0xFF000000, /* SEPNR    */
    0xFFF0FFF0, /* SMPRR_A  */
    0xFFF0FFF0, /* SMPRR_B  */
    0xFF008000, /* SEMSR    */
    0xF0F0FF00, /* SECNR    */
    0xE7000000, /* SERSR    */
    0xE7000000, /* SERMR    */
    0x00000001, /* SERCR    */
    0x00000000, /* reserved */
    0xFF0000E7, /* SIFCR_H  */
    0xFFFF8C30, /* SIFCR_L  */
    0xFF000000, /* SEFCR    */
    0xE7000000, /* SERFR    */
    0xFC00007F, /* SCVCR    */
    0xFC00007F  /* SMVCR    */
};

typedef struct {
    uint32_t sicfr   ; /* Global     Interrupt Configuration    Register */
    uint32_t sivcr   ; /* Regular    Interrupt Vector           Register */
    uint32_t scvcr   ; /* Critical   Interrupt Vector           Register */
    uint32_t smvcr   ; /* Management Interrupt Vector           Register */
    uint32_t simsr_l ; /* Internal   Interrupt Mask        Low  Register */
    uint32_t simsr_h ; /* Internal   Interrupt Mask        High Register */
    uint32_t sermr   ; /*            Error     Mask             Register */
    uint32_t semsr   ; /* External   Interrupt Mask             Register */
    uint32_t sipnr_l ; /* Internal   Interrupt Pending     Low  Register */
    uint32_t sipnr_h ; /* Internal   Interrupt Pending     High Register */
    uint32_t sepnr   ; /* External   Interrupt Pending          Register */
    uint32_t sicnr   ; /* Internal   Interrupt Control          Register */
    uint32_t secnr   ; /* External   Interrupt Control          Register */
    uint32_t sercr   ; /*            Error     Control          Register */
    uint32_t sersr   ; /*            Error     Status           Register */
    uint32_t siprr_a ; /* Internal   Interrupt Group A Priority Register */
    uint32_t siprr_b ; /* Internal   Interrupt Group B Priority Register */
    uint32_t siprr_c ; /* Internal   Interrupt Group C Priority Register */
    uint32_t siprr_d ; /* Internal   Interrupt Group D Priority Register */
    uint32_t smprr_a ; /* Mixed      Interrupt Group A Priority Register */
    uint32_t smprr_b ; /* Mixed      Interrupt Group B Priority Register */
    uint32_t sifcr_l ; /* Internal   Interrupt Force       Low  Register */
    uint32_t sifcr_h ; /* Internal   Interrupt Force       High Register */
    uint32_t sefcr   ; /* External   Interrupt Force            Register */
    uint32_t serfr   ; /*            Error     Force            Register */
} IPICRegisters;

#define IPIC_PRIORITY_DEFAULT 0x05309770

enum ipic_sicfr_bits {
    /*       HPI             1->7 */
    IPIC_BIT_MPSB = 1 << (31 -  9),
    IPIC_BIT_MPSA = 1 << (31 - 10),
    IPIC_BIT_IPSD = 1 << (31 - 12),
    IPIC_BIT_IPSA = 1 << (31 - 15)
    /*       HPIT          22->23 */
};
#define IPIC_BITS_HPI(sicfr)  ((sicfr & 0x7F000000) >> (31 -  7))
#define IPIC_BITS_HPIT(sicfr) ((sicfr & 0x00000300) >> (31 - 23))

enum ipic_sivcr_bits {
    /*         IVECx         0->5 */
    IPIC_SHIFT_IVECx =    31 -  5,
    /*         IVEC        25->31 */
    IPIC_SHIFT_IVEC  =    31 - 31
};
#define IPIC_MASK_IVECx 0x3f /* 6-bit (MPC8260 compatible) */
#define IPIC_MASK_IVEC  0x7f /* 7-bit */

struct ipic_source {
    uint8_t pending;   /* pending register offset */
    uint8_t mask;      /* mask register offset */
    uint8_t force;     /* force register offset */
    uint8_t bit;       /* register bit position, mask = 1 << (31 - bit) */
    uint8_t prio;      /* priority register offset */
    uint8_t prio_mask; /* priority mask value */
};

/* Index is Interrupt ID Number. See Table 8-6 MPC8349EARM */
static struct ipic_source ipic_sources[] = {
    [1] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 16,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 0,
    },
    [2] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 17,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 1,
    },
    [3] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 18,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 2,
    },
    [4] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 19,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 3,
    },
    [5] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 20,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 4,
    },
    [6] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 21,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 5,
    },
    [7] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 22,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 6,
    },
    [8] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 23,
        .prio      = IPIC_SIPRR_C,
        .prio_mask = 7,
    },
    [9] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 24,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 0,
    },
    [10] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 25,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 1,
    },
    [11] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 26,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 2,
    },
    [12] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 27,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 3,
    },
    [13] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 28,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 4,
    },
    [14] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 29,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 5,
    },
    [15] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 30,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 6,
    },
    [16] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 31,
        .prio      = IPIC_SIPRR_D,
        .prio_mask = 7,
    },
    [17] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 1,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 5,
    },
    [18] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 2,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 6,
    },
    [19] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 3,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 7,
    },
    [20] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 4,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 4,
    },
    [21] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 5,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 5,
    },
    [22] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 6,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 6,
    },
    [23] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 7,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 7,
    },
    [32] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 0,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 0,
    },
    [33] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 1,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 1,
    },
    [34] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 2,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 2,
    },
    [35] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 3,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 3,
    },
    [36] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 4,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 4,
    },
    [37] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 5,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 5,
    },
    [38] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 6,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 6,
    },
    [39] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 7,
        .prio      = IPIC_SIPRR_A,
        .prio_mask = 7,
    },
    [40] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 8,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 0,
    },
    [41] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 9,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 1,
    },
    [42] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 10,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 2,
    },
    [43] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 11,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 3,
    },
    [44] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 12,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 4,
    },
    [45] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 13,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 5,
    },
    [46] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 14,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 6,
    },
    [47] = {
        .pending   = IPIC_SIPNR_H,
        .mask      = IPIC_SIMSR_H,
        .force     = IPIC_SIFCR_H,
        .bit       = 15,
        .prio      = IPIC_SIPRR_B,
        .prio_mask = 7,
    },
    [48] = {
        .pending   = IPIC_SEPNR,
        .mask      = IPIC_SEMSR,
        .force     = IPIC_SEFCR,
        .bit       = 0,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 4,
    },
    [64] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 0,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 0,
    },
    [65] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 1,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 1,
    },
    [66] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 2,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 2,
    },
    [67] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 3,
        .prio      = IPIC_SMPRR_A,
        .prio_mask = 3,
    },
    [68] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 4,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 0,
    },
    [69] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 5,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 1,
    },
    [70] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 6,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 2,
    },
    [71] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 7,
        .prio      = IPIC_SMPRR_B,
        .prio_mask = 3,
    },
    [72] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 8,
    },
    [73] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 9,
    },
    [74] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 10,
    },
    [75] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 11,
    },
    [76] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 12,
    },
    [77] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 13,
    },
    [78] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 14,
    },
    [79] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 15,
    },
    [80] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 16,
    },
    [81] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 17,
    },
    [82] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 18,
    },
    [83] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 19,
    },
    [84] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 20,
    },
    [85] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 21,
    },
    [86] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 22,
    },
    [87] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 23,
    },
    [88] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 24,
    },
    [89] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 25,
    },
    [90] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 26,
    },
    [91] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 27,
    },
    [94] = {
        .pending   = IPIC_SIPNR_L,
        .mask      = IPIC_SIMSR_L,
        .force     = IPIC_SIFCR_L,
        .bit       = 30,
    }
};
#define IPIC_SOURCES_SIZE ARRAY_SIZE(ipic_sources)
#define IPIC_MASK(n)                 (1 << (31 - ipic_sources[n].bit))
#define IPIC_MASK_REG(s, n)          ((s)->regs_read[ipic_sources[n].mask])
#define IPIC_PENDING_REG(s, n)       ((s)->regs_read[ipic_sources[n].pending])
#define IPIC_FORCE_REG(s, n)         ((s)->regs_read[ipic_sources[n].force])
#define IPIC_PRIO_MASK(n)            ipic_sources[n].prio_mask

/* THE object */
typedef struct {

    /* board mapping */
    MemoryRegion mem;
    qemu_irq *out_irqs;

    /* registers */
    IPICRegisters regs;
    uint32_t     *regs_read[IPIC_REGS_SIZE];
    uint32_t     *regs_write[IPIC_REGS_SIZE];

} IPICState;

/* map the register variables with 2 arrays for read and write access */
static void ipic_init_registers_access(IPICState *s)
{
    /* structure is initialized with 0, so the unreferenced registers are
       NULL */
    #define IPIC_MAP_REGISTER_RW(reg, offset) \
        do { \
            if (ipic_reg_rw[IPIC_ ## offset] & IPIC_READ) { \
                s->regs_read[IPIC_ ## offset] = &s->regs.reg; \
            } \
            if (ipic_reg_rw[IPIC_ ## offset] & IPIC_WRITE) { \
                s->regs_write[IPIC_ ## offset] = &s->regs.reg; \
            } \
        } while (0)

    IPIC_MAP_REGISTER_RW(sicfr, SICFR);
    IPIC_MAP_REGISTER_RW(sivcr, SIVCR);
    IPIC_MAP_REGISTER_RW(sipnr_h, SIPNR_H);
    IPIC_MAP_REGISTER_RW(sipnr_l, SIPNR_L);
    IPIC_MAP_REGISTER_RW(siprr_a, SIPRR_A);
    IPIC_MAP_REGISTER_RW(siprr_b, SIPRR_B);
    IPIC_MAP_REGISTER_RW(siprr_c, SIPRR_C);
    IPIC_MAP_REGISTER_RW(siprr_d, SIPRR_D);
    IPIC_MAP_REGISTER_RW(simsr_h, SIMSR_H);
    IPIC_MAP_REGISTER_RW(simsr_l, SIMSR_L);
    IPIC_MAP_REGISTER_RW(sicnr, SICNR);
    IPIC_MAP_REGISTER_RW(sepnr, SEPNR);
    IPIC_MAP_REGISTER_RW(smprr_a, SMPRR_A);
    IPIC_MAP_REGISTER_RW(smprr_b, SMPRR_B);
    IPIC_MAP_REGISTER_RW(semsr, SEMSR);
    IPIC_MAP_REGISTER_RW(secnr, SECNR);
    IPIC_MAP_REGISTER_RW(sersr, SERSR);
    IPIC_MAP_REGISTER_RW(sermr, SERMR);
    IPIC_MAP_REGISTER_RW(sercr, SERCR);
    IPIC_MAP_REGISTER_RW(sifcr_h, SIFCR_H);
    IPIC_MAP_REGISTER_RW(sifcr_l, SIFCR_L);
    IPIC_MAP_REGISTER_RW(sefcr, SEFCR);
    IPIC_MAP_REGISTER_RW(serfr, SERFR);
    IPIC_MAP_REGISTER_RW(scvcr, SCVCR);
    IPIC_MAP_REGISTER_RW(smvcr, SMVCR);
}

/* save current state of the device in a file */
static void ipic_save(QEMUFile *file, void *state)
{
    IPICState *s = state;
    int reg;
    for (reg = 0; reg < IPIC_REGS_SIZE; reg++) {
        qemu_put_be32s(file, s->regs_read[reg]);
    }
}

/* load the device state from a file in a backward compatible way */
static int ipic_load(QEMUFile *file, void *state, int version)
{
    IPICState *s = state;
    int reg;
    if (version > IPIC_VERSION) {
        return -EINVAL;
    }
    for (reg = 0; reg < IPIC_REGS_SIZE; reg++) {
        qemu_get_be32s(file, s->regs_read[reg]);
    }
    return 0;
}

static void ipic_reset(void *state)
{
    IPICState *s = state;
    dprintf("reset\n");
    memset(&s->regs, 0, sizeof(IPICRegisters));
    s->regs.siprr_a = IPIC_PRIORITY_DEFAULT;
    s->regs.siprr_b = IPIC_PRIORITY_DEFAULT;
    s->regs.siprr_c = IPIC_PRIORITY_DEFAULT;
    s->regs.siprr_d = IPIC_PRIORITY_DEFAULT;
    s->regs.smprr_a = IPIC_PRIORITY_DEFAULT;
    s->regs.smprr_b = IPIC_PRIORITY_DEFAULT;
    s->regs.sermr   = 0xFF000000;
    /* TODO: set default value of SEPNR (= external input IRQs) */
    /* TODO: remove this nasty hack which makes the timebase working */
    s->regs.simsr_l = 0x40000000 /* PIT */;
}

static void ipic_raise_output_irq(IPICState *s, int source_id)
{
    /* update SIVCR to reflect the current IRQ source */
    s->regs.sivcr = ((source_id & IPIC_MASK_IVEC)  << IPIC_SHIFT_IVEC) |
                    ((source_id & IPIC_MASK_IVECx) << IPIC_SHIFT_IVECx);
    /* forward IRQ to the CPU */
    qemu_set_irq(s->out_irqs[IPIC_OUTPUT_INT], 1);
}

static void ipic_lower_output_irq(IPICState *s, int source_id)
{
    /* forward to CPU */
    qemu_set_irq(s->out_irqs[IPIC_OUTPUT_INT], 0);
}

/* check if an interrupt must be triggered */
static void ipic_check_mask(IPICState *s)
{
    int source_id;
    int count = 0;

    /* find the first source which should be triggered */
    /* TODO: handle priorities */
#if DEBUG_TRIGGER
    dprintf("trigger IRQs: ");
    for (source_id = 0; source_id < IPIC_SOURCES_SIZE; source_id++) {
	    const struct ipic_source *src = &ipic_sources[source_id];
	    uint32_t pending = *s->regs_read[src->pending];
	    uint32_t mask = *s->regs_read[src->mask];
	    uint32_t force = *s->regs_read[src->force];
        if (((force | pending) & mask & IPIC_MASK(source_id)) != 0) {
            dprintf0("#%d ", source_id);
            count++;
        }
    }
    dprintf0("\n");
#endif
    for (source_id = 0; source_id < IPIC_SOURCES_SIZE; source_id++) {
	    const struct ipic_source *src = &ipic_sources[source_id];
	    uint32_t pending = *s->regs_read[src->pending];
	    uint32_t mask = *s->regs_read[src->mask];
	    uint32_t force = *s->regs_read[src->force];
        if (((force | pending) & mask & IPIC_MASK(source_id)) != 0) {
            break;
        }
    }
    if (source_id == IPIC_SOURCES_SIZE) {
	ipic_lower_output_irq(s, source_id);
        return;
    }
    /* TODO: what should happen if many sources are unmasked at once ? */
    if (count > 1) {
        dprintf("WARNING: many sources unmasked at once\n");
    }
    /* trigger ISR */
    if (DEBUG_UNMASK) {
        dprintf("unmasked IRQ #%d\n", source_id);
    }
    ipic_raise_output_irq(s, source_id);
}

/* input IRQs are set by devices */
static void ipic_set_input_irq(void *state, int source_id, int level)
{
    IPICState *s = state;
    uint32_t *pending_reg;
    uint32_t source_mask;

    if (DEBUG_IRQ) {
        dprintf("set input IRQ #%d to %d\n", source_id, level);
    } else {
        if (DEBUG_IRQ_SET && level > 0) {
            dprintf("set input IRQ #%d to %d\n", source_id, level);
        }
    }

    /* get register and bit matching the source ID */
    pending_reg = IPIC_PENDING_REG(s, source_id);
    source_mask = IPIC_MASK(source_id);
    if (source_mask == 0) {
        if (DEBUG_IRQ) {
            eprintf("bad IRQ source number: #%d", source_id);
        }
        return;
    }

    if (level != 0) {
        /* source request an interrupt */
        if ((*pending_reg & source_mask) != 0) {
            /* IRQ is already pending */
            return;
        }
        /* set pending IRQ */
        *pending_reg |= source_mask;
        /* trigger interrupt if unmasked */
        if (*IPIC_MASK_REG(s, source_id) & source_mask) {
            ipic_raise_output_irq(s, source_id);
        } else {
            if (DEBUG_MASK) {
                dprintf("masked IRQ #%d\n", source_id);
            }
        }
    } else {
        /* end of ISR */
        if ((*pending_reg & source_mask) == 0) {
            /* IRQ is not pending and ISR is not running */
            return;
        }
        /* reset pending IRQ */
        *pending_reg &= ~source_mask;
        /* forward to CPU */
        ipic_lower_output_irq(s, source_id);
    }
}

static uint32_t *ipic_get_register(IPICState *s, IPICDirection direction,
                                   hwaddr address, int size, int *reg_offset)
{
    uint32_t *reg;
    int offset;

    /* get address of the register */
    offset = address & 0xff;

    /* check access: address and size must match */
    if ((offset & (size - 1)) != 0) {
        if (DEBUG_RW_ERROR) {
            dprintf("access to an unaligned address (%d-bit at 0x%02X)\n",
                    size << 3, offset);
        }
        return NULL;
    }

    /* all registers are 32-bit wide */
    *reg_offset = offset >> 2;
    /* check access range */
    if (*reg_offset >= IPIC_REGS_SIZE) {
        if (DEBUG_RW_ERROR) {
            dprintf("access to an invalid address (0x%02X)\n", offset);
        }
        return NULL;
    }

    /* get register */
    if (direction == IPIC_READ) {
        reg = s->regs_read[*reg_offset];
    } else if (direction == IPIC_WRITE) {
        reg = s->regs_write[*reg_offset];
    } else {
        return NULL;
    }

    if (reg == NULL) {
        /* check access: some registers are read-only or reserved */
        if (DEBUG_RW_ERROR) {
            dprintf("unauthorized %s register 0x%02X (%s)\n",
              IPIC_IO_STR(direction), offset, ipic_reg_name[*reg_offset]);
        }
    } else {
        if (DEBUG_RW_REG(*reg_offset)) {
            dprintf("%d-bit %s register 0x%02X (%s ",
              size << 3, IPIC_IO_STR(direction), offset,
              ipic_reg_name[*reg_offset]);
        }
    }

    return reg;
}

static void ipic_compute_io(hwaddr address, int size,
                            int *bit_offset, uint32_t *size_mask)
{
    /* registers are 32-bit wide */
    *bit_offset = (address & 3) << 8;

    *size_mask = size > 3 ? 0xffffffff : (1 << (size << 3)) - 1;
}

static uint64_t ipic_read(void *state, hwaddr address, unsigned size)
{
    IPICState *s = state;
    uint32_t *reg, reg_mask, size_mask;
    int reg_offset, bit_offset;

    reg = ipic_get_register(s, IPIC_READ, address, size, &reg_offset);
    if (reg == NULL) {
        return 0;
    }
    if (DEBUG_RW_REG(reg_offset)) {
        dprintf0("= 0x%08X)\n", *reg);
    }

    /* do specific actions */
    switch (reg_offset) {
    }

    /* return value */
    ipic_compute_io(address, size, &bit_offset, &size_mask);
    reg_mask = ipic_reg_mask[reg_offset];
    return ((*reg & reg_mask) >> bit_offset) & size_mask;
}

static void ipic_write(void *state, hwaddr address, uint64_t value,
                       unsigned size)
{
    IPICState *s = state;
    uint32_t *reg, full_value, reg_mask, size_mask, unchanged_mask;
    int reg_offset, bit_offset;

    reg = ipic_get_register(s, IPIC_WRITE, address, size, &reg_offset);
    if (reg == NULL) {
        return;
    }

    /* set value */
    ipic_compute_io(address, size, &bit_offset, &size_mask);
    full_value = (value & size_mask) << bit_offset;
    if (DEBUG_RW_REG(reg_offset)) {
        dprintf0("= 0x%08X)\n", full_value);
    }
    reg_mask = ipic_reg_mask[reg_offset];
    unchanged_mask = 0xffffffff ^ (size_mask << bit_offset);
    *reg = (*reg & unchanged_mask) | (full_value & reg_mask);

    /* do specific actions */
    switch (reg_offset) {
    case IPIC_SIMSR_L:
    case IPIC_SIMSR_H:
    case IPIC_SEMSR:
    case IPIC_SIFCR_L:
    case IPIC_SIFCR_H:
    case IPIC_SEFCR:
        ipic_check_mask(s);
        break;
    }
}

static const MemoryRegionOps ipic_ops = {
    .write = ipic_write,
    .read  = ipic_read,
    .endianness = DEVICE_BIG_ENDIAN,
};

/* main function: initialization
 * outputs are given as parameter
 * inputs are returned */
qemu_irq *ipic_init(MemoryRegion *address_space, hwaddr base_addr,
                    qemu_irq out_irqs[IPIC_OUTPUT_SIZE])
{
    IPICState *s = NULL;
    qemu_irq *in_irqs = NULL;

    if (DEBUG_CONFIG) {
        dprintf("mapped at address 0x%08X\n", (uint32_t)base_addr);
    }

    /* instantiate the object and initialize it to 0 */
    s = g_malloc0(sizeof(IPICState));
    memory_region_init_io(&s->mem, NULL, &ipic_ops, s, "ipic", IPIC_MEM_SIZE);
    memory_region_add_subregion(address_space, base_addr, &s->mem);

    /* initialize registers with their default value */
    ipic_reset(s);

    /* initialize read/write accesses to the registers */
    ipic_init_registers_access(s);

    /* initialize input IRQs for devices */
    in_irqs = qemu_allocate_irqs(ipic_set_input_irq, s, IPIC_SOURCES_SIZE);

    /* save output IRQs to core */
    s->out_irqs = out_irqs;

    /* register a hard reset used by qemu */
    qemu_register_reset(ipic_reset, s);

    /* register functions to suspend/resume the current state */
    register_savevm(NULL, "IPIC", 0, IPIC_VERSION, ipic_save, ipic_load, s);

    return in_irqs;
}

// Imported from https://github.com/cillianodonnell/couverture_qemu/blob/patches/hw/ppc/wrSbc834x.h

#ifndef PPC83XX_H
#define PPC83XX_H

#include "qemu-common.h"

#define e300_VECTOR_MASK  0x000fffff
#define e300_RESET_VECTOR 0x00000100

typedef struct mpc83xx_config {
    uint32_t ccsr_init_addr;
    const char *cpu_model;
} mpc83xx_config;

CPUState *mpc83xx_init(mpc83xx_config *config,
                         ram_addr_t ram_size,
                         const char *boot_device,
                         const char *kernel_filename,
                         const char *kernel_cmdline,
                         const char *initrd_filename,
                         const char *cpu_model);

#endif /* PPC83XX_H */

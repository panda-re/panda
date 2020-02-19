// Imported from: https://github.com/cillianodonnell/couverture_qemu/blob/patches/hw/intc/ipic.h

#ifndef IPIC_H
#define IPIC_H

#include "qemu-common.h"

enum ipic_output_irqs {
    IPIC_OUTPUT_INT    , /* internal main                 Interrupt */
    IPIC_OUTPUT_CINT   , /* internal Critical             Interrupt */
    IPIC_OUTPUT_SMI    , /* internal System Management    Interrupt */
    IPIC_OUTPUT_MCP    , /* internal Machine Check Processor signal */
    IPIC_OUTPUT_INTA   , /* external                      Interrupt */
    IPIC_OUTPUT_MCP_OUT, /* external Machine Check Processor signal */
    IPIC_OUTPUT_SIZE
};

qemu_irq *ipic_init(MemoryRegion *address_space, hwaddr base_addr,
                    qemu_irq out_irqs[IPIC_OUTPUT_SIZE]);

#endif /* IPIC_H */

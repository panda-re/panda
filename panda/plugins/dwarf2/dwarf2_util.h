
#ifndef __DWARF2_UTIL_H
#define __DWARF2_UTIL_H

#include "panda/plugin.h"
#include "pri/pri_types.h"


// util functions to read DW_OP char array
const unsigned char *
read_uleb128 (const unsigned char *p, target_ulong *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    target_ulong result;

    result = 0;
    do
    {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    *val = result;
    return p;
}

/* Similar, but read a signed leb128 value.  */

    const unsigned char *
read_sleb128 (const unsigned char *p, target_long *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    target_ulong result;

    result = 0;
    do
    {
        byte = *p++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    }
    while (byte & 0x80);

    /* Sign-extend a negative value.  */
    if (shift < 8 * sizeof(result) && (byte & 0x40) != 0)
        result |= -(1L << shift);

    *val = (target_long) result;
    return p;
}



/* util functions for execute_stack_op that basically facilitate reading from memory */
union unaligned
{
    void *p;
    unsigned u2 __attribute__ ((mode (HI)));
    unsigned u4 __attribute__ ((mode (SI)));
    unsigned u8 __attribute__ ((mode (DI)));
    signed s2 __attribute__ ((mode (HI)));
    signed s4 __attribute__ ((mode (SI)));
    signed s8 __attribute__ ((mode (DI)));
} __attribute__ ((packed));

target_ulong
read_guest_pointer (CPUState *cpu, target_ulong guest_addr) { 
    target_ulong out;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *)&out, sizeof(target_ulong), 0); 
    return out; 
}

static inline int
read_1u (CPUState *cpu, target_ulong guest_addr) { 
    unsigned char c;
    panda_virtual_memory_rw(cpu, guest_addr, &c, 1, 0); 
    return c;
}

static inline int
read_1s (CPUState *cpu, target_ulong guest_addr) { 
    unsigned char c;
    panda_virtual_memory_rw(cpu, guest_addr, &c, 1, 0); 
    return c;
}

static inline int
read_2u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u2;
}

static inline int
read_2s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s2;
}

static inline unsigned int
read_4u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u4;
}

static inline int
read_4s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s4;
}

static inline unsigned long
read_8u (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.u8;
}

static inline unsigned long
read_8s (CPUState *cpu, target_ulong guest_addr) { 
    union unaligned up;
    panda_virtual_memory_rw(cpu, guest_addr, (uint8_t *) &up, sizeof(up), 0); 
    return up.s8;
}

/* Get the value of register REG as saved in CONTEXT.  */

    inline target_ulong
getReg (CPUState *cpu, int index)
{
    /* This will segfault if the register hasn't been saved.  */
    /* not sure if we dereference register or simply get value  */
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
#if defined(TARGET_I386) || defined(TARGET_ARM)
    return env->regs[index];
#elif defined(TARGET_PPC)
    return env->gpr[index];
#elif defined(TARGET_MIPS)
    return env->active_tc.gpr[index];
#else
    /*
     * We need this last else because otherwise this function in this
     * plugin breaks build on new architectures.
    */
    return 0; 
#endif
}



#endif

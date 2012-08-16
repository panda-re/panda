// Helpers for working with i8259 interrupt controller.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
#ifndef __PIC_H
#define __PIC_H

#include "ioport.h" // PORT_PIC*
#include "biosvar.h" // SET_IVT

// PORT_PIC1 bitdefs
#define PIC1_IRQ0  (1<<0)
#define PIC1_IRQ1  (1<<1)
#define PIC1_IRQ2  (1<<2)
#define PIC1_IRQ5  (1<<5)
#define PIC1_IRQ6  (1<<6)
// PORT_PIC2 bitdefs
#define PIC2_IRQ8  (1<<0)
#define PIC2_IRQ12 (1<<4)
#define PIC2_IRQ13 (1<<5)
#define PIC2_IRQ14 (1<<6)

static inline void
eoi_pic1(void)
{
    // Send eoi (select OCW2 + eoi)
    outb(0x20, PORT_PIC1_CMD);
}

static inline void
eoi_pic2(void)
{
    // Send eoi (select OCW2 + eoi)
    outb(0x20, PORT_PIC2_CMD);
    eoi_pic1();
}

static inline void
unmask_pic1(u8 irq)
{
    outb(inb(PORT_PIC1_DATA) & ~irq, PORT_PIC1_DATA);
}

static inline void
unmask_pic2(u8 irq)
{
    outb(inb(PORT_PIC2_DATA) & ~irq, PORT_PIC2_DATA);
}

static inline void
mask_pic1(u8 irq)
{
    outb(inb(PORT_PIC1_DATA) | irq, PORT_PIC1_DATA);
}

static inline void
mask_pic2(u8 irq)
{
    outb(inb(PORT_PIC2_DATA) | irq, PORT_PIC2_DATA);
}

static inline u8
get_pic1_isr(void)
{
    // 0x0b == select OCW1 + read ISR
    outb(0x0b, PORT_PIC1_CMD);
    return inb(PORT_PIC1_CMD);
}

static inline u8
get_pic2_isr(void)
{
    // 0x0b == select OCW1 + read ISR
    outb(0x0b, PORT_PIC2_CMD);
    return inb(PORT_PIC2_CMD);
}

static inline void
enable_hwirq(int hwirq, struct segoff_s func)
{
    int vector;
    if (hwirq < 8) {
        unmask_pic1(1 << hwirq);
        vector = 0x08 + hwirq;
    } else {
        unmask_pic2(1 << (hwirq - 8));
        vector = 0x70 + hwirq - 8;
    }
    SET_IVT(vector, func);
}

void set_pics(u8 irq0, u8 irq8);
void pic_setup(void);

#endif // pic.h

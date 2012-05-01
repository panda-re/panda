// Helpers for working with i8259 interrupt controller.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "pic.h" // get_pic1_isr
#include "util.h" // dprintf
#include "config.h" // CONFIG_*

void
set_pics(u8 irq0, u8 irq8)
{
    // Send ICW1 (select OCW1 + will send ICW4)
    outb(0x11, PORT_PIC1_CMD);
    outb(0x11, PORT_PIC2_CMD);
    // Send ICW2 (base irqs: 0x08-0x0f for irq0-7, 0x70-0x77 for irq8-15)
    outb(irq0, PORT_PIC1_DATA);
    outb(irq8, PORT_PIC2_DATA);
    // Send ICW3 (cascaded pic ids)
    outb(0x04, PORT_PIC1_DATA);
    outb(0x02, PORT_PIC2_DATA);
    // Send ICW4 (enable 8086 mode)
    outb(0x01, PORT_PIC1_DATA);
    outb(0x01, PORT_PIC2_DATA);
    // Mask all irqs (except cascaded PIC2 irq)
    outb(~PIC1_IRQ2, PORT_PIC1_DATA);
    outb(~0, PORT_PIC2_DATA);
}

void
pic_setup(void)
{
    dprintf(3, "init pic\n");
    set_pics(0x08, 0x70);
}

// Handler for otherwise unused hardware irqs.
void VISIBLE16
handle_hwpic1(struct bregs *regs)
{
    dprintf(DEBUG_ISR_hwpic1, "handle_hwpic1 irq=%x\n", get_pic1_isr());
    eoi_pic1();
}

void VISIBLE16
handle_hwpic2(struct bregs *regs)
{
    dprintf(DEBUG_ISR_hwpic2, "handle_hwpic2 irq=%x\n", get_pic2_isr());
    eoi_pic2();
}

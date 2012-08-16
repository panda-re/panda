/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdint.h>

//*******************************************************************
// variable "tb_freq" contains the frequency in Hz
// and is read from the device tree (setup by LLFW) in "init.c"
uint64_t tb_freq;

//-------------------------------------------------------------------
// Read the current timebase
uint64_t get_time(void)
{
    uint64_t act;

    __asm__ __volatile__( 
        "0:     mftbu   %0 ;\
                mftbl   %%r0 ; \
                mftbu   %%r4 ; \
                cmpw    %0,%%r4 ; \
                bne     0b; \
                sldi    %0,%0,32; \
                or      %0,%0,%%r0"
        : "=r"(act)
        : /* no inputs */
        : "r0", "r4");
    return act;
}

//-------------------------------------------------------------------
// wait for ticks/scale timebase ticks
void wait_ticks(uint64_t ticks)
{
        uint64_t timeout = get_time() + ticks;
        while (get_time() < timeout) {
                unsigned int i;
                for (i = 1000; i > 0; i--)
                        __asm__ __volatile__ ("" : : : "memory");
        }
}

//-------------------------------------------------------------------
// wait for (at least) usecs microseconds
void udelay(unsigned int usecs)
{
        // first multiply the usec with timebase and then devide
        // because 1.000.000 is relatively huge compared to usecs
        wait_ticks((usecs*tb_freq)/1000000);
}

//-------------------------------------------------------------------
// wait for (at least) msecs milliseconds
void mdelay(unsigned int msecs)
{
        // first multiply the msec and timebase and then devide
        // because 1.000 is relatively huge compared to msecs
        wait_ticks((msecs*tb_freq)/1000);
}

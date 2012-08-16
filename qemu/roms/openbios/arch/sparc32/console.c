/*
 * Copyright (C) 2003, 2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "config.h"
#include "kernel/kernel.h"
#include "drivers/drivers.h"
#include "openbios.h"
#include "libopenbios/console.h"
#include "libopenbios/ofmem.h"

void cls(void);

#ifdef CONFIG_DEBUG_CONSOLE

/* ******************************************************************
 *          simple polling video/keyboard console functions
 * ****************************************************************** */

#ifdef CONFIG_DEBUG_CONSOLE_VIDEO

#define VMEM_BASE 0x00800000ULL
#define VMEM_SIZE (1024*768*1)
#define DAC_BASE  0x00200000ULL
#define DAC_SIZE  16

unsigned char *vmem;
volatile uint32_t *dac;

static void video_putchar(int c)
{
    char buf;

    buf = c & 0xff;

    console_draw_fstr(&buf, 1);
}

static void video_cls(void)
{
    memset((void *)vmem, 0, VMEM_SIZE);
}

void tcx_init(uint64_t base)
{
    vmem = (unsigned char *)ofmem_map_io(base + VMEM_BASE, VMEM_SIZE);
    dac = (uint32_t *)ofmem_map_io(base + DAC_BASE, DAC_SIZE);

    console_init();
}

#endif

/* ******************************************************************
 *      common functions, implementing simple concurrent console
 * ****************************************************************** */

int putchar(int c)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	serial_putchar(c);
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	video_putchar(c);
#endif
	return c;
}

int availchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return 1;
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	if (keyboard_dataready())
		return 1;
#endif
	return 0;
}

int getchar(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	if (uart_charav(CONFIG_SERIAL_PORT))
		return (uart_getchar(CONFIG_SERIAL_PORT));
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	if (keyboard_dataready())
		return (keyboard_readdata());
#endif
	return 0;
}

void cls(void)
{
#ifdef CONFIG_DEBUG_CONSOLE_SERIAL
	serial_cls();
#endif
#ifdef CONFIG_DEBUG_CONSOLE_VIDEO
	video_cls();
#endif
}


#endif				// CONFIG_DEBUG_CONSOLE

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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <of.h>
#include <pci.h>
#include <cpu.h>
#include <takeover.h>

extern void call_client_interface(of_arg_t *);

#define boot_rom_bin_start _binary_______boot_rom_bin_start
#define boot_rom_bin_end   _binary_______boot_rom_bin_end

extern char boot_rom_bin_start;
extern char boot_rom_bin_end;

#if defined(__GNUC__)
# define UNUSED __attribute__((unused))
#else
# define UNUSED
#endif


/*
 * These functions are just dummy implemented to resolve symbols for linking to other objects
 */

int
open(const char *name UNUSED, int flags UNUSED)
{
	return 0;
}

int
close(int fd UNUSED)
{
	return 0;
}

ssize_t
read(int fd UNUSED, void *buf UNUSED, size_t count UNUSED)
{
	return 0;
}

int
ioctl(int fd UNUSED, int req UNUSED, void *data UNUSED)
{
	return 0;
}

/*
 * These functions are required for using libc.a
 */
ssize_t
write(int fd, const void *buf, size_t len)
{
	char  dst_buf[512];
	char *dst_buf_ptr;
	char *src_buf_ptr;
	int i;

	src_buf_ptr = (char *) buf;
	if (fd == 1 || fd == 2)
	{
		dst_buf_ptr = &dst_buf[0];
		for (i = 0; i < len && i < 256; i++)
		{
			*dst_buf_ptr++ = *src_buf_ptr++;
			if (src_buf_ptr[-1] == '\n')
				*dst_buf_ptr++ = '\r';
		}
		len = dst_buf_ptr - &dst_buf[0];
		src_buf_ptr = &dst_buf[0];
	}

	if(fd < 0 || fd >= FILEIO_MAX
	|| fd_array[fd].type == FILEIO_TYPE_EMPTY
	|| fd_array[fd].write == 0)
		return -1;

	return fd_array[fd].write(&fd_array[fd], src_buf_ptr, len);
}

void *
sbrk(int incr)
{
	return (void *) -1;
}

void
doWait(void)
{
	static const char *wheel = "|/-\\";
	static int i = 0;
	volatile int dly = 0xf0000;
	while (dly--);
	printf("\b%c", wheel[i++]);
	i &= 0x3;
}

void
quiesce(void)
{
	of_arg_t arg = {
		p32cast "quiesce",
		0, 0,
	};
	call_client_interface(&arg);
}

int
startCpu(int num, int addr, int reg)
{
	of_arg_t arg = {
		p32cast "start-cpu",
		3, 0,
		{num, addr, reg}
	};
	call_client_interface(&arg);
	return arg.args[3];
}

volatile unsigned long slaveQuitt;
int takeoverFlag;

void
main(int argc, char *argv[])
{
	phandle_t cpus;
	phandle_t cpu;
	unsigned long slaveMask;
	extern int slaveLoop[];
	extern int slaveLoopNoTakeover[];
	int rcode;
	int index = 0;
	int delay = 100;
	unsigned long reg;
	unsigned long msr;
	asm volatile ("mfmsr %0":"=r" (msr));
	if (msr & 0x1000000000000000)
		takeoverFlag = 0;
	else
		takeoverFlag = 1;

	cpus = of_finddevice("/cpus");
	cpu = of_child(cpus);
	slaveMask = 0;
	while (cpu) {
		char devType[100];
		*devType = '\0';
		of_getprop(cpu, "device_type", devType, sizeof(devType));
		if (strcmp(devType, "cpu") == 0) {
			of_getprop(cpu, "reg", &reg, sizeof(reg));
			if (index) {
				printf("\r\n takeover on cpu%d (%x, %lx) ", index,
				       cpu, reg);
				slaveQuitt = -1;
				if (takeoverFlag)
					startCpu(cpu, (int)(unsigned long)slaveLoop, index);
				else
					startCpu(cpu, (int)(unsigned long)slaveLoopNoTakeover,
						 index);
				slaveMask |= 0x1 << index;
				delay = 100;
				while (delay-- && slaveQuitt)
					doWait();
			}
			index++;
		}
		cpu = of_peer(cpu);
	}


	printf("\r\n takeover on master cpu  ");
	quiesce();

	delay = 5;
	while (delay--)
		doWait();
	if (takeoverFlag)
		rcode = takeover();

	memcpy((void*)TAKEOVERBASEADDRESS, &boot_rom_bin_start, &boot_rom_bin_end - &boot_rom_bin_start);
	flush_cache((void *)TAKEOVERBASEADDRESS, &boot_rom_bin_end - &boot_rom_bin_start);
	index = 0;

	while (slaveMask) {
		unsigned long shifter = 0x1 << index;
		if (shifter & slaveMask) {
			slaveQuitt = index;
			while (slaveQuitt);
			slaveMask &= ~shifter;
		}
		index++;
	}

	asm volatile(" mtctr %0 ; bctr " : : "r" (TAKEOVERBASEADDRESS+0x180) );
}

int
callback(int argc, char *argv[])
{
	/* Dummy, only for takeover */
	return (0);
}

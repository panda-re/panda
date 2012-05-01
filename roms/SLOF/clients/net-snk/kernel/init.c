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

#include <of.h>
#include <pci.h>
#include <kernel.h>
#include <stdint.h>
#include <string.h>
#include <cpu.h>
#include <fileio.h>
#include <stdlib.h> /* malloc */
#include <ioctl.h> /* ioctl */

/* Application entry point .*/
extern int _start(unsigned char *arg_string, long len);
extern int main(int, char**);
void * malloc_aligned(size_t size, int align);
extern snk_module_t *insmod_by_type(int);
extern void rmmod_by_type(int);

unsigned long exception_stack_frame;

snk_fileio_t fd_array[FILEIO_MAX];

extern uint64_t tb_freq;

void modules_init(void);
void modules_term(void);
int glue_init(snk_kernel_t *, unsigned int *, size_t, size_t);
void glue_release(void);

static char save_vector[0x4000];
extern char _lowmem_start;
extern char _lowmem_end;
extern char __client_start;
extern char __client_end;

snk_kernel_t snk_kernel_interface = {
	.version          = 1,
	.print            = printk,
	.us_delay         = udelay,
	.ms_delay         = mdelay,
	.k_malloc         = malloc,
	.k_malloc_aligned = malloc_aligned,
	.k_free           = free,
	.strcmp           = strcmp,
	.snk_call         = main,
	.k_open           = open,
	.k_close          = close,
	.k_read           = read,
	.k_write          = write,
	.k_ioctl          = ioctl,
	.modules_remove   = rmmod_by_type,
	.modules_load     = insmod_by_type,
};

void *
malloc_aligned(size_t size, int align)
{
	unsigned long p = (unsigned long) malloc(size + align - 1);
	p = p + align - 1;
	p = p & ~(align - 1);

	return (void *) p;
}

static void
copy_exception_vectors()
{
	char *dest;
	char *src;
	int len;

	dest = save_vector;
	src = (char *) 0x200;
	len = &_lowmem_end - &_lowmem_start;
	memcpy(dest, src, len);

	dest = (char *) 0x200;
	src = &_lowmem_start;
	memcpy(dest, src, len);
	flush_cache(dest, len);
}

static void
restore_exception_vectors()
{
	char *dest;
	char *src;
	int len;

	dest = (char *) 0x200;
	src = save_vector;
	len = &_lowmem_end - &_lowmem_start;
	memcpy(dest, src, len);
	flush_cache(dest, len);
}

int
_start_kernel(unsigned long p0, unsigned long p1)
{
	int rc;
	unsigned int timebase;

	/* initialize all file descriptor by marking them as empty */
	for(rc=0; rc<FILEIO_MAX; ++rc) {
		fd_array[rc].type = FILEIO_TYPE_EMPTY;
		fd_array[rc].idx  = rc;
	}

	/* this is step is e.g. resposible to initialize file descriptor 0 and 1 for STDIO */
	rc = glue_init(&snk_kernel_interface, &timebase, (size_t)(unsigned long)&__client_start,
	               (size_t)(unsigned long)&__client_end - (size_t)(unsigned long)&__client_start);
	if(rc < 0)
		return -1;

	tb_freq = (uint64_t) timebase;
	copy_exception_vectors();
	modules_init();
	rc = _start((unsigned char *) p0, p1);
	modules_term();
	restore_exception_vectors();

	glue_release();
	return rc;
}


void
exception_forward(void)
{
	restore_exception_vectors();
	undo_exception();
}

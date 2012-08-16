/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

OUTPUT_FORMAT("elf64-powerpc", "elf64-powerpc", "elf64-powerpc")
OUTPUT_ARCH(powerpc:common64)
ENTRY(module_init)

SECTIONS {
	.code 0xF800000:
	{
	  __module_start = .;
	  ../common/module_entry.o(.opd) 
	  *(.text .stub .text.* .gnu.linkonce.t.*)
	  *(.sfpr .glink)
	  *(.rodata .rodata.* .gnu.linkonce.r.*)
	  *(.data .data.* .gnu.linkonce.d.*)
	  *(.opd)
	} 
	.got : 
	{
	  _got = .;
	  *(.got .toc)
	} 
	.bss :
	{
	  __bss_start = .;
	  *(*COM* .bss .gnu.linkonce.b.*)
	  __bss_end = .;
	} 
	__module_end = .;
}

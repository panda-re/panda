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


#include <macros.h>

	.section	".toc","aw"	# TOC entries are needed for relocation
.exception_stack_frame_toc:
	.tc		exception_stack_frame[TC],exception_stack_frame
.system_call_toc:
	.tc		_system_call[TC],_system_call


	.section	.lowmem,"aw",@progbits

	.irp i, 0x0200,0x0300,0x0380,0x0400,0x0480,0x0500,0x0600,0x0700, \
		0x0800,0x0900,0x0a00,0x0b00
	. = \i - 0x200
// 0	
	stdu	r1, -0x58(r1)
	std	r0, 0x30(r1)
	mflr	r0
	std	r0, 0x38(r1)
// 10
	mfsrr0	r0
	std	r0, 0x48(r1)	
	mfsrr1	r0
	std	r0, 0x50(r1)	
// 20
	std	r11, 0x40(r1)
 	li	r0, \i
	ld	r11, 0x60 + \i(0)
	bl	_exception_handler

// 30
	ld	r0, 0x48(r1)	
	mtsrr0	r0
	ld	r0, 0x50(r1)	
	mtsrr1	r0

// 40
	ld	r0, 0x38(r1)
	mtlr	r0	
	ld	r0, 0x30(r1)
	ld	r11, 0x40(r1)
// 50
	addi 	r1, r1, 0x58
	rfid
	nop
	nop
// 60	
//	.quad	\i+0x68	
	.quad	.exception_forward		
// 68
	blr
	.endr

	# System call entry
	. = 0xc00 - 0x200

	stdu	r1, -0x50(r1)
	mflr	r11
	std	r11, 0x30(r1)
	mfsrr0	r11
	std	r11, 0x40(r1)
	mfsrr1	r11
	std	r11, 0x48(r1)
	ld	r11, .system_call_toc@toc(r2)
	ld	r11, 0(r11)
	mtctr	r11
	mr	r10, r0
	bctrl
	ld	r11, 0x30(r1)
	mtlr	r11
	ld	r11, 0x40(r1)	
	mtsrr0	r11
	ld	r11, 0x48(r1)	
	mtsrr1	r11
	addi	r1, r1, 0x50
	rfid
	
	.irp i, 0x0d00,0x0e00,0x0f00, \
		0x1000,0x1100,0x1200,0x1300,0x1400,0x1500,0x1600,0x1700, \
		0x1800,0x1900,0x1a00,0x1b00,0x1c00,0x1d00,0x1e00,0x1f00, \
		0x2000,0x2100,0x2200,0x2300,0x2400,0x2500,0x2600,0x2700, \
		0x2800,0x2900,0x2a00,0x2b00,0x2c00,0x2d00,0x2e00,0x2f00
	. = \i - 0x200
// 0	
	stdu	r1, -0x58(r1)
	std	r0, 0x30(r1)
	mflr	r0
	std	r0, 0x38(r1)
// 10
	mfsrr0	r0
	std	r0, 0x48(r1)	
	mfsrr1	r0
	std	r0, 0x50(r1)	
// 20
	std	r11, 0x40(r1)
 	li	r0, \i
	ld	r11, 0x60 + \i(0)
	bl	_exception_handler

// 30
	ld	r0, 0x48(r1)	
	mtsrr0	r0
	ld	r0, 0x50(r1)	
	mtsrr1	r0

// 40
	ld	r0, 0x38(r1)
	mtlr	r0	
	ld	r0, 0x30(r1)
	ld	r11, 0x40(r1)
// 50
	addi 	r1, r1, 0x58
	rfid
	nop
	nop
// 60	
//	.quad	\i+0x68	
	.quad	.exception_forward		
// 68
	blr
	.endr

/* Saves all register potential clobbered in exception handler.
   In r0 the pointer to the function is passed.
 */

_exception_handler:
    stdu	r1, -0x130(r1)	
	.irp i, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, \
	        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, \
		27, 28, 29, 30, 31
	std	r\i, 0x30+\i*8 (r1)
	.endr
	mfctr   r14
	std	r14,0x130(r1)
	mtctr	r11

	LOAD64(r3,_entry)
	ld	r2,8(r3)

	ld	r3,.exception_stack_frame_toc@toc(r2)
	std	r1,0(r3)

	mflr	r14
	bctrl	
	mtlr	r14

	ld 	r14,0x130(r1)
	mtctr	r14
/*
	mfsrr0	r2
	addi	r2, r2, 4
	mtsrr0	r2
*/
	.irp i, 2,3,4,5,6,7,8,9,10,12,13,14,15,16, \
	        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, \
		27, 28, 29, 30, 31
	ld	r\i, 0x30+\i*8 (r1)
	.endr
    addi	r1, r1, 0x130
	blr 

	.text
	
/* Set exception handler for given exception vector.  
	r3:	exception vector offset
	r4:	exception handler
*/	
	.globl .set_exception
.set_exception:
	.globl set_exception
set_exception:
    ld r4,0x0(r4)
	.globl .set_exception_asm
.set_exception_asm:
	.globl set_exception_asm
set_exception_asm:
	std	r4, 0x60(r3)	# fixme diff 1f - 0b
	blr 	


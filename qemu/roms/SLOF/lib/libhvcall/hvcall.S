#define _ASM
#define __ASSEMBLY__
#include "macros.h"
#include "libhvcall.h"
	
#define HVCALL			.long 0x44000022
	
	.text
	.align	3

ENTRY(hv_generic)
	HVCALL
	blr

ENTRY(hv_putchar)
	sldi	r6,r3,(24+32)
	li	r3,H_PUT_TERM_CHAR
	li	r4,0
	li	r5,1
	HVCALL
	blr

ENTRY(hv_getchar)
	mflr	r10
	bl	.hv_haschar
	mtlr	r10
	cmpwi	cr0,r3,0
	beqlr
	lis	r9,inbuf@h
	ori	r9,r9,inbuf@l
	lwz	r4,20(r9)
	lbzx	r3,r4,r9
	addi	r4,r4,1
	stw	r4,20(r9)
	blr

ENTRY(hv_haschar)
	li	r3,-1
	lis	r9,inbuf@h
	ori	r9,r9,inbuf@l
	lwz	r5,16(r9)
	lwz	r6,20(r9)
	cmplw	cr0,r5,r6
	bnelr
	li	r3,H_GET_TERM_CHAR
	li	r4,0
	HVCALL
	lis	r9,inbuf@h
	ori	r9,r9,inbuf@l
	stw	r4,16(r9)
	li	r3,0
	stw	r3,20(r9)
	cmplwi	cr0,r4,0
	beqlr
	li	r3,-1
	std	r5,0(r9)
	std	r6,8(r9)
	blr

ENTRY(hv_send_crq)
	ld	r5,0(r4)
	ld	r6,8(r4)
	mr	r4,r3
	li	r3,H_SEND_CRQ
	HVCALL
	blr

ENTRY(hv_send_logical_lan)
	li	r11,0	/* no continue token for now */
	mr	r10,r9
	mr	r9,r8
	mr	r8,r7
	mr	r7,r6
	mr	r6,r5
	mr	r5,r4
	mr	r4,r3
	li	r3,H_SEND_LOGICAL_LAN
	HVCALL
	blr

	.section ".bss"
 inbuf:	.space	16
inlen:	.space	4
inpos:	.space	4
	.text
	
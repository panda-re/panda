\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

( eva - gordons fcode bytecode evaluator )

hex

-1 constant true
 0 constant false

variable ip
variable fcode-end 
variable fcode-num
 1 value fcode-spread
16 value fcode-offset
false value eva-debug?
false value fcode-debug?
defer fcode-rb@
defer fcode@

' c@ to fcode-rb@

create token-table 2000 cells allot    \ 1000h = 4096d

include core.fs
include 1275.fs
include tokens.fs

0 value buff
0 value buff-size

( ---------------------------------------------------- )

' read-fcode# to fcode@

: step next-ip fcode@ exec ; immediate
( ---------------------------------------------------- )

: rom-code-ignored ( image# name len -- )
    diagnostic-mode? IF type ."  code found in image " .  ." , ignoring ..." cr
    ELSE 3drop THEN
;

: pci-find-rom ( baseaddr -- addr )
    -8 and dup IF
	dup rw@ 55aa = IF
		diagnostic-mode? IF ." Device ROM found at " dup . cr THEN
	ELSE drop 0 THEN
    THEN
;

: pci-find-fcode ( baseaddr -- addr len | false )
    pci-find-rom ?dup IF
	dup 18 + rw@ wbflip +
	0 swap BEGIN
	    dup rl@ 50434952 ( 'PCIR') <> IF
		diagnostic-mode? IF
			." Invalid PCI Data structure, ignoring ROM contents" cr
		THEN
		2drop false EXIT
	    THEN
	    dup 14 + rb@ CASE
		0 OF over . s" Intel x86 BIOS" rom-code-ignored ENDOF
		1 OF swap diagnostic-mode? IF
				." Open Firmware FCode found at image " . cr
			ELSE drop THEN
			dup a + rw@ wbflip over + \ This code start
			swap 10 + rw@ wbflip 200 * \ This code length
			EXIT
		ENDOF
		2 OF over . s" HP PA RISC" rom-code-ignored ENDOF
		3 OF over . s" EFI" rom-code-ignored ENDOF
		dup OF over . s" Unknown type" rom-code-ignored ENDOF
	    ENDCASE
	    dup 15 + rb@ 80 and IF 2drop EXIT THEN \ End of last image
	    dup 10 + rw@ wbflip 200 * + \ Next image start
	    swap 1+ swap \ Next image #
	0 UNTIL
    THEN false
;

: execute-rom-fcode ( addr len | false -- )
	?dup IF
		diagnostic-mode? IF ." , executing ..." cr THEN
		dup >r r@ alloc-mem dup >r swap rmove
		r@ set-ip evaluate-fcode
		diagnostic-mode? IF ." Done." cr THEN
		r> r> free-mem
	THEN
;

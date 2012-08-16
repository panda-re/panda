// Rom layout and bios assembler to C interface.
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.


/****************************************************************
 * Include of 16bit C code
 ****************************************************************/

        .code16gcc
#include "vgaccode.16.s"

#include "entryfuncs.S" // ENTRY_*


/****************************************************************
 * Rom Header
 ****************************************************************/

        .section .rom.header
        .global _rom_header, _rom_header_size, _rom_header_checksum
_rom_header:
        .word 0xaa55
_rom_header_size:
        .byte 0
_rom_header_entry:
        jmp _optionrom_entry
_rom_header_checksum:
        .byte 0
_rom_header_other:
        .space 21


/****************************************************************
 * Entry points
 ****************************************************************/

        DECLFUNC _optionrom_entry
_optionrom_entry:
        ENTRY_ARG vga_post
        lretw

        DECLFUNC entry_10
entry_10:
        ENTRY_ARG handle_10
        iretw

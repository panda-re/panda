/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file Table for converting Dalvik opcodes to strings
 * @Author Lok Yan
 */
#ifndef DALVIK_OPCODE_TABLE_H
#define DALVIK_OPCODE_TABLE_H

/**
 * 256 total possible Opcodes
 */
#define DALVIK_OPCODE_TABLE_LEN 256

/**
 * Default for any opcode outside of range
 */
static const char* DALVIK_INVALID_OPCODE = "INVALID";

/**
 * The opcode table.
 */
static const char* DalvikOpcodeTable[DALVIK_OPCODE_TABLE_LEN] = {
    /* 0x00 */
    "nop",
    "move",
    "move/from16",
    "move/16",
    "move-wide",
    "move-wide/from16",
    "move-wide/16",
    "move-object",
    "move-object/from16",
    "move-object/16",
    "move-result",
    "move-result-wide",
    "move-result-object",
    "move-exception",
    "return-void",
    "return",

    /* 0x10 */
    "return-wide",
    "return-object",
    "const/4",
    "const/16",
    "const",
    "const/high16",
    "const-wide/16",
    "const-wide/32",
    "const-wide",
    "const-wide/high16",
    "const-string",
    "const-string/jumbo",
    "const-class",
    "monitor-enter",
    "monitor-exit",
    "check-cast",

    /* 0x20 */
    "instance-of",
    "array-length",
    "new-instance",
    "new-array",
    "filled-new-array",
    "filled-new-array/range",
    "fill-array-data",
    "throw",
    "goto",
    "goto/16",
    "goto/32",
    "packed-switch",
    "sparse-switch",
    "cmpl-float",
    "cmpg-float",
    "cmpl-double",

    /* 0x30 */
    "cmpg-double",
    "cmp-long",
    "if-eq",
    "if-ne",
    "if-lt",
    "if-ge",
    "if-gt",
    "if-le",
    "if-eqz",
    "if-nez",
    "if-ltz",
    "if-gez",
    "if-gtz",
    "if-lez",
    "UNUSED",
    "UNUSED",

    /* 0x40 */
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "aget",
    "aget-wide",
    "aget-object",
    "aget-boolean",
    "aget-byte",
    "aget-char",
    "aget-short",
    "aput",
    "aput-wide",
    "aput-object",
    "aput-boolean",
    "aput-byte",

    /* 0x50 */
    "aput-char",
    "aput-short",
    "iget",
    "iget-wide",
    "iget-object",
    "iget-boolean",
    "iget-byte",
    "iget-char",
    "iget-short",
    "iput",
    "iput-wide",
    "iput-object",
    "iput-boolean",
    "iput-byte",
    "iput-char",
    "iput-short",

    /* 0x60 */
    "sget",
    "sget-wide",
    "sget-object",
    "sget-boolean",
    "sget-byte",
    "sget-char",
    "sget-short",
    "sput",
    "sput-wide",
    "sput-object",
    "sput-boolean",
    "sput-byte",
    "sput-char",
    "sput-short",
    "invoke-virtual",
    "invoke-super",

    /* 0x70 */
    "invoke-direct",
    "invoke-static",
    "invoke-interface",
    "UNUSED",
    "invoke-virtual/range",
    "invoke-super/range",
    "invoke-direct/range",
    "invoke-static/range",
    "invoke-interface/range",
    "UNUSED",
    "UNUSED",
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "neg-float",

    /* 0x80 */
    "neg-double",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "long-to-float",
    "long-to-double",
    "float-to-int",
    "float-to-long",
    "float-to-double",
    "double-to-int",
    "double-to-long",
    "double-to-float",
    "int-to-byte",
    "int-to-char",
    "int-to-short",

    /* 0x90 */
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long",

    /* 0xa0 */
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double",

    /* 0xb0 */
    "add-int/2addr",
    "sub-int/2addr",
    "mul-int/2addr",
    "div-int/2addr",
    "rem-int/2addr",
    "and-int/2addr",
    "or-int/2addr",
    "xor-int/2addr",
    "shl-int/2addr",
    "shr-int/2addr",
    "ushr-int/2addr",
    "add-long/2addr",
    "sub-long/2addr",
    "mul-long/2addr",
    "div-long/2addr",
    "rem-long/2addr",

    /* 0xc0 */
    "and-long/2addr",
    "or-long/2addr",
    "xor-long/2addr",
    "shl-long/2addr",
    "shr-long/2addr",
    "ushr-long/2addr",
    "add-float/2addr",
    "sub-float/2addr",
    "mul-float/2addr",
    "div-float/2addr",
    "rem-float/2addr",
    "add-double/2addr",
    "sub-double/2addr",
    "mul-double/2addr",
    "div-double/2addr",
    "rem-double/2addr",

    /* 0xd0 */
    "add-int/lit16",
    "rsub-int",
    "mul-int/lit16",
    "div-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit16",
    "add-int/lit8",
    "rsub-int/lit8",
    "mul-int/lit8",
    "div-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "xor-int/lit8",

    /* 0xe0 */
    "shl-int/lit8",
    "shr-int/lit8",
    "ushr-int/lit8",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "^breakpoint",                  // does not appear in DEX files
    "^throw-verification-error",    // does not appear in DEX files
    "+execute-inline",
    "+execute-inline/range",

    /* 0xf0 */
    "+invoke-direct-empty",
    "UNUSED",
    "+iget-quick",
    "+iget-wide-quick",
    "+iget-object-quick",
    "+iput-quick",
    "+iput-wide-quick",
    "+iput-object-quick",
    "+invoke-virtual-quick",
    "+invoke-virtual-quick/range",
    "+invoke-super-quick",
    "+invoke-super-quick/range",
    "UNUSED",
    "UNUSED",
    "UNUSED",
    "UNUSED",
};

#define OP_nop          (0x0)
#define OP_move         (0x1)
#define OP_move_from16          (0x2)
#define OP_move_16              (0x3)
#define OP_move_wide            (0x4)
#define OP_move_wide_from16             (0x5)
#define OP_move_wide_16         (0x6)
#define OP_move_object          (0x7)
#define OP_move_object_from16           (0x8)
#define OP_move_object_16               (0x9)
#define OP_move_result          (0xA)
#define OP_move_result_wide             (0xB)
#define OP_move_result_object           (0xC)
#define OP_move_exception               (0xD)
#define OP_return_void          (0xE)
#define OP_return               (0xF)

/* 0x10 */
#define OP_return_wide          (0x10)
#define OP_return_object                (0x11)
#define OP_const_4              (0x12)
#define OP_const_16             (0x13)
#define OP_const                (0x14)
#define OP_const_high16         (0x15)
#define OP_const_wide_16                (0x16)
#define OP_const_wide_32                (0x17)
#define OP_const_wide           (0x18)
#define OP_const_wide_high16            (0x19)
#define OP_const_string         (0x1A)
#define OP_const_string_jumbo           (0x1B)
#define OP_const_class          (0x1C)
#define OP_monitor_enter                (0x1D)
#define OP_monitor_exit         (0x1E)
#define OP_check_cast           (0x1F)

/* 0x20 */
#define OP_instance_of          (0x20)
#define OP_array_length         (0x21)
#define OP_new_instance         (0x22)
#define OP_new_array            (0x23)
#define OP_filled_new_array             (0x24)
#define OP_filled_new_array_range               (0x25)
#define OP_fill_array_data              (0x26)
#define OP_throw                (0x27)
#define OP_goto         (0x28)
#define OP_goto_16              (0x29)
#define OP_goto_32              (0x2A)
#define OP_packed_switch                (0x2B)
#define OP_sparse_switch                (0x2C)
#define OP_cmpl_float           (0x2D)
#define OP_cmpg_float           (0x2E)
#define OP_cmpl_double          (0x2F)

/* 0x30 */
#define OP_cmpg_double          (0x30)
#define OP_cmp_long             (0x31)
#define OP_if_eq                (0x32)
#define OP_if_ne                (0x33)
#define OP_if_lt                (0x34)
#define OP_if_ge                (0x35)
#define OP_if_gt                (0x36)
#define OP_if_le                (0x37)
#define OP_if_eqz               (0x38)
#define OP_if_nez               (0x39)
#define OP_if_ltz               (0x3A)
#define OP_if_gez               (0x3B)
#define OP_if_gtz               (0x3C)
#define OP_if_lez               (0x3D)
//#define OP_UNUSED               (0x3E)
//#define OP_UNUSED               (0x3F)

/* 0x40 */
//#define OP_UNUSED               (0x40)
//#define OP_UNUSED               (0x41)
//#define OP_UNUSED               (0x42)
//#define OP_UNUSED               (0x43)
#define OP_aget         (0x44)
#define OP_aget_wide            (0x45)
#define OP_aget_object          (0x46)
#define OP_aget_boolean         (0x47)
#define OP_aget_byte            (0x48)
#define OP_aget_char            (0x49)
#define OP_aget_short           (0x4A)
#define OP_aput         (0x4B)
#define OP_aput_wide            (0x4C)
#define OP_aput_object          (0x4D)
#define OP_aput_boolean         (0x4E)
#define OP_aput_byte            (0x4F)

/* 0x50 */
#define OP_aput_char            (0x50)
#define OP_aput_short           (0x51)
#define OP_iget         (0x52)
#define OP_iget_wide            (0x53)
#define OP_iget_object          (0x54)
#define OP_iget_boolean         (0x55)
#define OP_iget_byte            (0x56)
#define OP_iget_char            (0x57)
#define OP_iget_short           (0x58)
#define OP_iput         (0x59)
#define OP_iput_wide            (0x5A)
#define OP_iput_object          (0x5B)
#define OP_iput_boolean         (0x5C)
#define OP_iput_byte            (0x5D)
#define OP_iput_char            (0x5E)
#define OP_iput_short           (0x5F)

/* 0x60 */
#define OP_sget         (0x60)
#define OP_sget_wide            (0x61)
#define OP_sget_object          (0x62)
#define OP_sget_boolean         (0x63)
#define OP_sget_byte            (0x64)
#define OP_sget_char            (0x65)
#define OP_sget_short           (0x66)
#define OP_sput         (0x67)
#define OP_sput_wide            (0x68)
#define OP_sput_object          (0x69)
#define OP_sput_boolean         (0x6A)
#define OP_sput_byte            (0x6B)
#define OP_sput_char            (0x6C)
#define OP_sput_short           (0x6D)
#define OP_invoke_virtual               (0x6E)
#define OP_invoke_super         (0x6F)

/* 0x70 */
#define OP_invoke_direct                (0x70)
#define OP_invoke_static                (0x71)
#define OP_invoke_interface             (0x72)
//#define OP_UNUSED               (0x73)
#define OP_invoke_virtual_range         (0x74)
#define OP_invoke_super_range           (0x75)
#define OP_invoke_direct_range          (0x76)
#define OP_invoke_static_range          (0x77)
#define OP_invoke_interface_range               (0x78)
//#define OP_UNUSED               (0x79)
//#define OP_UNUSED               (0x7A)
#define OP_neg_int              (0x7B)
#define OP_not_int              (0x7C)
#define OP_neg_long             (0x7D)
#define OP_not_long             (0x7E)
#define OP_neg_float            (0x7F)

/* 0x80 */
#define OP_neg_double           (0x80)
#define OP_int_to_long          (0x81)
#define OP_int_to_float         (0x82)
#define OP_int_to_double                (0x83)
#define OP_long_to_int          (0x84)
#define OP_long_to_float                (0x85)
#define OP_long_to_double               (0x86)
#define OP_float_to_int         (0x87)
#define OP_float_to_long                (0x88)
#define OP_float_to_double              (0x89)
#define OP_double_to_int                (0x8A)
#define OP_double_to_long               (0x8B)
#define OP_double_to_float              (0x8C)
#define OP_int_to_byte          (0x8D)
#define OP_int_to_char          (0x8E)
#define OP_int_to_short         (0x8F)

/* 0x90 */
#define OP_add_int              (0x90)
#define OP_sub_int              (0x91)
#define OP_mul_int              (0x92)
#define OP_div_int              (0x93)
#define OP_rem_int              (0x94)
#define OP_and_int              (0x95)
#define OP_or_int               (0x96)
#define OP_xor_int              (0x97)
#define OP_shl_int              (0x98)
#define OP_shr_int              (0x99)
#define OP_ushr_int             (0x9A)
#define OP_add_long             (0x9B)
#define OP_sub_long             (0x9C)
#define OP_mul_long             (0x9D)
#define OP_div_long             (0x9E)
#define OP_rem_long             (0x9F)

/* 0xa0 */
#define OP_and_long             (0xA0)
#define OP_or_long              (0xA1)
#define OP_xor_long             (0xA2)
#define OP_shl_long             (0xA3)
#define OP_shr_long             (0xA4)
#define OP_ushr_long            (0xA5)
#define OP_add_float            (0xA6)
#define OP_sub_float            (0xA7)
#define OP_mul_float            (0xA8)
#define OP_div_float            (0xA9)
#define OP_rem_float            (0xAA)
#define OP_add_double           (0xAB)
#define OP_sub_double           (0xAC)
#define OP_mul_double           (0xAD)
#define OP_div_double           (0xAE)
#define OP_rem_double           (0xAF)

/* 0xb0 */
#define OP_add_int_2addr                (0xB0)
#define OP_sub_int_2addr                (0xB1)
#define OP_mul_int_2addr                (0xB2)
#define OP_div_int_2addr                (0xB3)
#define OP_rem_int_2addr                (0xB4)
#define OP_and_int_2addr                (0xB5)
#define OP_or_int_2addr         (0xB6)
#define OP_xor_int_2addr                (0xB7)
#define OP_shl_int_2addr                (0xB8)
#define OP_shr_int_2addr                (0xB9)
#define OP_ushr_int_2addr               (0xBA)
#define OP_add_long_2addr               (0xBB)
#define OP_sub_long_2addr               (0xBC)
#define OP_mul_long_2addr               (0xBD)
#define OP_div_long_2addr               (0xBE)
#define OP_rem_long_2addr               (0xBF)

/* 0xc0 */
#define OP_and_long_2addr               (0xC0)
#define OP_or_long_2addr                (0xC1)
#define OP_xor_long_2addr               (0xC2)
#define OP_shl_long_2addr               (0xC3)
#define OP_shr_long_2addr               (0xC4)
#define OP_ushr_long_2addr              (0xC5)
#define OP_add_float_2addr              (0xC6)
#define OP_sub_float_2addr              (0xC7)
#define OP_mul_float_2addr              (0xC8)
#define OP_div_float_2addr              (0xC9)
#define OP_rem_float_2addr              (0xCA)
#define OP_add_double_2addr             (0xCB)
#define OP_sub_double_2addr             (0xCC)
#define OP_mul_double_2addr             (0xCD)
#define OP_div_double_2addr             (0xCE)
#define OP_rem_double_2addr             (0xCF)

/* 0xd0 */
#define OP_add_int_lit16                (0xD0)
#define OP_rsub_int             (0xD1)
#define OP_mul_int_lit16                (0xD2)
#define OP_div_int_lit16                (0xD3)
#define OP_rem_int_lit16                (0xD4)
#define OP_and_int_lit16                (0xD5)
#define OP_or_int_lit16         (0xD6)
#define OP_xor_int_lit16                (0xD7)
#define OP_add_int_lit8         (0xD8)
#define OP_rsub_int_lit8                (0xD9)
#define OP_mul_int_lit8         (0xDA)
#define OP_div_int_lit8         (0xDB)
#define OP_rem_int_lit8         (0xDC)
#define OP_and_int_lit8         (0xDD)
#define OP_or_int_lit8          (0xDE)
#define OP_xor_int_lit8         (0xDF)

/* 0xe0 */
#define OP_shl_int_lit8         (0xE0)
#define OP_shr_int_lit8         (0xE1)
#define OP_ushr_int_lit8                (0xE2)
//#define OP_UNUSED               (0xE3)
//#define OP_UNUSED               (0xE4)
//#define OP_UNUSED               (0xE5)
//#define OP_UNUSED               (0xE6)
//#define OP_UNUSED               (0xE7)
//#define OP_UNUSED               (0xE8)
//#define OP_UNUSED               (0xE9)
//#define OP_UNUSED               (0xEA)
//#define OP_UNUSED               (0xEB)
#define OP_breakpoint                  (0xEC)
#define OP_throw_verification_error    (0xED)
#define OP_execute_inline              (0xEE)
#define OP_execute_inline_range                (0xEF)

/* 0xf0 */
#define OP_invoke_direct_empty         (0xF0)
//#define OP_UNUSED               (0xF1)
#define OP_iget_quick          (0xF2)
#define OP_iget_wide_quick             (0xF3)
#define OP_iget_object_quick           (0xF4)
#define OP_iput_quick          (0xF5)
#define OP_iput_wide_quick             (0xF6)
#define OP_iput_object_quick           (0xF7)
#define OP_invoke_virtual_quick                (0xF8)
#define OP_invoke_virtual_quick_range          (0xF9)
#define OP_invoke_super_quick          (0xFA)
#define OP_invoke_super_quick_range            (0xFB)
//#define OP_UNUSED               (0xFC)
//#define OP_UNUSED               (0xFD)
//#define OP_UNUSED               (0xFE)
//#define OP_UNUSED               (0xFF)

static inline int isDalvikInvoke(int opcode)
{
  return ( (opcode == 0xf0) //invoke-direct-empty
           || ( (opcode >= 0xf8) && (opcode <= 0xfb) ) //invoke-virtual-quick to invoke-super-quick/range
           || ( (opcode >= 0x70) && (opcode <= 0x78) && (opcode != 0x73) ) //invoke-direct to invoke-interface/range
         );
}

static inline int isDalvikReturn(int opcode)
{
  return ( (opcode >= 0x0e) && (opcode <= 0x11) );
}

static inline int isDalvikMoveResult(int opcode)
{
  return ( (opcode >= OP_move_result) && (opcode <= OP_move_exception));
}

static inline int isDalvikExecute(int opcode)
{
  return ( (opcode == OP_execute_inline) || (opcode == OP_execute_inline_range) );
}
/**
 * Looks up the opcode in the table.
 * @param opcode The opcode number
 * @return The string corresponding to the opcode if its supported, or INVALID if out of range.
 */
static inline const char* dalvikOpcodeToString(int opcode)
{
  if ( (opcode < 0) || (opcode >= DALVIK_OPCODE_TABLE_LEN) )
  {
    return DALVIK_INVALID_OPCODE;
  }
  return DalvikOpcodeTable[opcode];
}

/**
 * Turns an address into a Dalvik opcode number
 */
static inline uint32_t mterpAddrToOpcode(gva_t iBase, gva_t addr)
{
  if (addr < iBase) //because rIBase is an unsigned int, INV_ADDR is the max_int which is good
  {
    return (INV_ADDR);
  }

  if (addr & 0x3F) //check that the first six bits are 0
  {
    return (INV_ADDR);
  }

  uint32_t ret = (addr - iBase) >> 6; //subtract and then shift it to the right 6 bits (which is the same as divided by 64)

  if (ret >= DALVIK_OPCODE_TABLE_LEN)
  {
    return (INV_ADDR);
  }

  return (ret);
}
#endif//DALVIK_OPCODE_TABLE_H

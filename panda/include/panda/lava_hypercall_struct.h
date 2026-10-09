/*!
 * @file lava_hypercall_struct.h
 * @brief Support for hypercalls from the PANDA guest to the taint2 plugin. Used by LAVA.
 *
 * @author
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * @copyright This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */
#pragma once
#ifndef __LAVA_HYPERCALL_STRUCT_H__
#define __LAVA_HYPERCALL_STRUCT_H__

#ifndef __cplusplus
#define static_assert _Static_assert
#endif

static_assert(sizeof(unsigned int) == 4, "unsigned int must be 4 bytes");
static_assert(sizeof(unsigned long long) == 8, "unsigned long long must be 8 bytes");

#define LAVA_MAGIC 0xabcd

#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
  #pragma pack(push, 1)
#else
  #error "Unknown compiler: packing rules not defined"
#endif

typedef struct PandaHypercallStruct {
    unsigned int action;             //  0 - label / query / etc
    unsigned int buf;                //  4 - ptr to memory
    unsigned int len;                //  8 - number of bytes
    unsigned int label_num;          // 12 - label number
    unsigned int src_column;         // 16 - column on source line
    unsigned int src_filename;       // 20 - char * to filename
    unsigned int src_linenum;        // 24 - line number
    unsigned int src_ast_node_name;  // 28 - l-value queries
    unsigned long long info;         // 32 - general info / 64-bit stack anchor address
    unsigned int insertion_point;    // 40 - unused
} PandaHypercallStruct;

#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
  #pragma pack(pop)
#endif

/* =========================
 *  ABI verification
 * ========================= */
static_assert(sizeof(PandaHypercallStruct) == 44, "PandaHypercallStruct size must be exactly 44 bytes");

static_assert(__builtin_offsetof(PandaHypercallStruct, action) == 0, "action offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, buf) == 4, "buf offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, len) == 8, "len offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, label_num) == 12, "label_num offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_column) == 16, "src_column offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_filename) == 20, "src_filename offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_linenum) == 24, "src_linenum offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_ast_node_name) == 28, "src_ast_node_name offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, info) == 32, "info offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, insertion_point) == 40, "insertion_point offset");

#endif // __LAVA_HYPERCALL_STRUCT_H__
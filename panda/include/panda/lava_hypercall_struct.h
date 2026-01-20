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

#define LAVA_MAGIC 0xabcd

#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
  #pragma pack(push, 1)
#else
  #error "Unknown compiler: packing rules not defined"
#endif

typedef struct PandaHypercallStruct {
    unsigned int magic;              //  0 - Must be LAVA_MAGIC
    unsigned int action;             //  4 - label / query / etc
    unsigned int buf;                //  8 - ptr to memory we want labeled or queried or ...
    unsigned int len;                // 12 - number of bytes to label or query or ...
    unsigned int label_num;          // 16 - if labeling, this is the label number.  if querying this should be zero
    unsigned int src_column;         // 20 - column on source line
    unsigned int src_filename;       // 24 - char * to filename.
    unsigned int src_linenum;        // 28 - line number
    unsigned int src_ast_node_name;  // 32 - the name of the l-value queries
    unsigned int info;               // 36 - general info
    unsigned int insertion_point;    // 40 - unused now 
} PandaHypercallStruct;

#if defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
  #pragma pack(pop)
#endif

/* =========================
 *  ABI verification
 * ========================= */
static_assert(sizeof(PandaHypercallStruct) == 44, "PandaHypercallStruct size must be exactly 44 bytes");

/* Offset checks — these catch silent packing drift */
static_assert(__builtin_offsetof(PandaHypercallStruct, magic) == 0, "magic offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, action) == 4, "action offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, buf) == 8, "buf offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, len) == 12, "len offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, label_num) == 16, "label_num offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_column) == 20, "src_column offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_filename) == 24, "src_filename offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_linenum) == 28, "src_linenum offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, src_ast_node_name) == 32, "src_ast_node_name offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, info) == 36, "info offset");
static_assert(__builtin_offsetof(PandaHypercallStruct, insertion_point) == 40, "insertion_point offset");

#endif // __LAVA_HYPERCALL_STRUCT_H__

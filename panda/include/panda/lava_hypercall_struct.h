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

// lavaint must be 32 bits for architecture compatibility (4 bytes)
typedef unsigned int lavaint;
#ifndef __cplusplus
#define static_assert _Static_assert
#endif
static_assert(sizeof(lavaint) == 4, "lavaint size must be 4!");

// Magic number used by the host to identify the hypercall as a legitimate
// call intended for the taint2 plugin.
#define LAVA_MAGIC 0xabcd

// CRITICAL: Ensure 1-byte packing so the structure size and field offsets
// match exactly between the guest and the host (no compiler padding).
#pragma pack(push,1)
typedef struct panda_hypercall_struct {
    lavaint magic;              // Must be LAVA_MAGIC
    lavaint action;             // label / query / etc
    lavaint buf;                // ptr to memory we want labeled or queried or ...
    lavaint len;                // number of bytes to label or query or ...
    lavaint label_num;          // if labeling, this is the label number.  if querying this should be zero
    lavaint src_column;         // column on source line
    lavaint src_filename;       // char * to filename.  
    lavaint src_linenum;        // line number
    lavaint src_ast_node_name;  // the name of the l-value queries 
    lavaint info;               // general info
    lavaint insertion_point;    // unused now.
} PandaHypercallStruct;
#pragma pack(pop)

#endif // __LAVA_HYPERCALL_STRUCT_H__
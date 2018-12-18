/*!
 * @file taint2_hypercalls.h
 * @brief Support for hypercalls from the PANDA guest to the taint2 plugin.
 *
 * @note This is currently only used by LAVA. Make sure you keep this file
 * in sync between the PANDA and LAVA repositories.
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
#ifndef TAINT2_HYPERCALLS_H
#define TAINT2_HYPERCALLS_H
#ifdef TAINT2_HYPERCALLS

#include "qemu/osdep.h"

typedef unsigned int lavaint;
#ifndef __cplusplus
#define static_assert _Static_assert
#endif
static_assert(sizeof(lavaint) == 4, "lavaint size must be 4!");

#pragma pack(push,1)
typedef struct panda_hypercall_struct {
    lavaint magic;
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

#ifdef __cplusplus
extern "C" {
#endif
int guest_hypercall_callback(CPUState *cpu);
#ifdef __cplusplus
}
#endif

#endif
#endif

#ifndef __PANDA_HYPERCALL_STRUCT_H__
#define __PANDA_HYPERCALL_STRUCT_H__

// For LAVA use only

/*
 * Keep me in sync between PANDA and LAVA repos
 */

#ifdef PANDA
#include "stdint.h"
typedef uint32_t lavaint;
#else
typedef unsigned int lavaint;
#endif

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
} PandaHypercallStruct;
#pragma pack(pop)

#endif


#ifndef __PANDA_HYPERCALL_STRUCT_H__
#define __PANDA_HYPERCALL_STRUCT_H__

#include "inttypes.h"

// For LAVA use only

/*
 * Keep me in sync between PANDA and LAVA repos
 */

typedef struct panda_hypercall_struct {
  uint64_t action;      // label / query / etc
  uint64_t buf;         // ptr to memory we want labeled or queried or ...
  uint32_t len;         // number of bytes to label or query or ...
  uint32_t label_num;   // if labeling, this is the label number.  if querying this should be zero
  //  uint32_t offset;      // offset is used for what?
  uint64_t src_filename;  // if querying from src this is a char * to filename.  
  uint64_t src_linenum;   // if querying from src this is the line number
  uint64_t src_ast_node_name;     // if querying from src this is the name of the l-value queries 
} PandaHypercallStruct;

#endif


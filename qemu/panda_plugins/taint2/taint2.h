/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
 PANDAENDCOMMENT */

/*

   API for Taint processor

*/

#ifndef __TAINT_PROCESSOR_H__
#define __TAINT_PROCESSOR_H__

#include <stdint.h>

#include <map>
#include <set>

#include "defines.h"

//#define TAINTDEBUG // print out all debugging info for taint ops

typedef struct FastShad FastShad;
typedef struct LabelSet *LabelSetP;
typedef struct SdDir32 SdDir32;
typedef struct SdDir64 SdDir64;
typedef struct addr_struct Addr;

typedef void (*on_branch_t) (LabelSetP);

// Unused for now.
typedef enum {
    TAINT_BINARY_LABEL,
    TAINT_BYTE_LABEL
} TaintLabelMode;

typedef enum {
    TAINT_GRANULARITY_BYTE,
    TAINT_GRANULARITY_WORD
} TaintGranularity;

typedef struct shad_struct {
    uint64_t hd_size;
    uint32_t mem_size;
    uint64_t io_size;
    uint32_t port_size;
    uint32_t num_vals;
    uint32_t guest_regs;
    SdDir64 *hd;
    FastShad *ram;
    SdDir64 *io;
    SdDir32 *ports;
    FastShad *llv;  // LLVM registers, with multiple frames
    FastShad *ret;  // LLVM return value, also temp register
    FastShad *grv;  // guest general purpose registers
    FastShad *gsv;  // guest special values, like FP, and parts of CPUState
    uint32_t max_obs_ls_type;
    uint64_t asid;
    uint64_t pc;
    uint64_t prev_bb; // label for previous BB.

    TaintLabelMode mode;
    TaintGranularity granularity;
} Shad;

// returns a shadow memory to be used by taint processor
Shad *tp_init(TaintLabelMode mode, TaintGranularity granularity);

// Delete a shadow memory
void tp_free(Shad *shad);

// label -- associate label l with address a
void tp_label(Shad *shad, Addr *a, uint32_t l);

std::set<uint32_t> tp_query(Shad *shad, Addr *a);

void tp_label_ram(Shad *shad, uint64_t pa, uint32_t l);

uint32_t tp_query_ram(Shad *shad, uint64_t pa) ;

uint32_t tp_query_reg(Shad *shad, int reg_num, int offset);

void tp_delete_ram(Shad *shad, uint64_t pa) ;

#endif

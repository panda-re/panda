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

#ifndef __TAINT2_H__
#define __TAINT2_H__

#include <stdint.h>

#include <map>
#include <set>

#include "defines.h"

//#define TAINTDEBUG // print out all debugging info for taint ops

typedef const std::set<uint32_t> *LabelSetP;
typedef struct FastShad FastShad;
typedef struct SdDir32 SdDir32;
typedef struct SdDir64 SdDir64;
typedef struct addr_struct Addr;

typedef void (*on_branch2_t) (Addr);
typedef void (*on_taint_change_t) (Addr);

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


void tp_label_ram(Shad *shad, uint64_t pa, uint32_t l);

LabelSetP tp_query(Shad *shad, Addr a);
LabelSetP tp_query_ram(Shad *shad, uint64_t pa) ;
LabelSetP tp_query_reg(Shad *shad, int reg_num, int offset);
LabelSetP tp_query_llvm(Shad *shad, int reg_num, int offset);

uint32_t tp_query_tcn(Shad *shad, Addr a);
uint32_t tp_query_tcn_ram(Shad *shad, uint64_t pa);
uint32_t tp_query_tcn_reg(Shad *shad, int reg_num, int offset);
uint32_t tp_query_tcn_llvm(Shad *shad, int reg_num, int offset);


// label set cardinality
uint32_t ls_card(LabelSetP ls);

void tp_delete_ram(Shad *shad, uint64_t pa) ;

void tp_ls_iter(LabelSetP ls, int (*app)(uint32_t el, void *stuff1), void *stuff2) ;

void tp_ls_ram_iter(Shad *shad, uint64_t pa, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void tp_ls_reg_iter(Shad *shad, int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);
void tp_ls_llvm_iter(Shad *shad, int reg_num, int offset, int (*app)(uint32_t el, void *stuff1), void *stuff2);

// returns set of so-far applied labels as a sorted array
// NB: This allocates memory. Caller frees.
uint32_t *tp_labels_applied(void);

// just tells how big that labels_applied set will be
uint32_t tp_num_labels_applied(void);

Addr make_haddr(uint64_t a);
Addr make_maddr(uint64_t a);
Addr make_laddr(uint64_t a, uint64_t o);
Addr make_iaddr(uint64_t a);
Addr make_paddr(uint64_t a);
Addr make_greg(uint64_t r, uint16_t off);


#endif

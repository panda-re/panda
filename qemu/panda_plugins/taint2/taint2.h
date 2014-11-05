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

#include "cpu.h"
#include "fast_shad.h"
#include "shad_dir_32.h"
#include "shad_dir_64.h"
#include "panda_memlog.h"

#include <map>
#include <set>

#define EXCEPTIONSTRING "3735928559"  // 0xDEADBEEF read from dynamic log
#define OPNAMELENGTH 15
#define FUNCNAMELENGTH 50
#define FUNCTIONFRAMES 10 // handle 10 frames for now, should be sufficient
#define MAXREGSIZE 16 // Maximum LLVM register size is 16 bytes

//#define TAINTDEBUG // print out all debugging info for taint ops

// Unused for now.
typedef enum {
    TAINT_BINARY_LABEL,
    TAINT_BYTE_LABEL
} TaintLabelMode;

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
    uint8_t tainted_computation_happened;
    uint64_t asid;
    uint64_t pc;
   // map from cr3 to set of pcs that are "tainted" meaning they are instructions that process tainted data
    std::map < uint64_t, std::set < uint64_t > > tpc;  
} Shad;

// returns a shadow memory to be used by taint processor
Shad *tp_init(uint64_t hd_size, uint32_t mem_size, uint64_t io_size, uint32_t max_vals);

// Delete a shadow memory
void tp_free(Shad *shad);

// label -- associate label l with address a
void tp_label(Shad *shad, Addr *a, uint32_t l);

LabelSet *tp_query(Shad *shad, Addr *a);

typedef void (*on_load_t) (uint64_t tp_pc, uint64_t addr);
typedef void (*on_store_t) (uint64_t tp_pc, uint64_t addr);
typedef void (*before_execute_taint_ops_t) (void);
typedef void (*after_execute_taint_ops_t) (void);

#endif

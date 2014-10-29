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

typedef struct FastShad FastShad;

void taint_copy(uintptr_t shad_dest_ptr, uint64_t dest, uint64_t shad_src_ptr, uint64_t src, uint64_t size);

// Two compute models: parallel and mixed. Parallel for bitwise, mixed otherwise.
// Parallel compute: take labelset vectors [1,2,3] + [4,5,6] -> [14,25,36]
void taint_parallel(uintptr_t shad_ptr, uint64_t dest, uint64_t src1, uint64_t src2, uint64_t size);

// Union all labels within here: [1,2,3] + [4,5,6] -> [123456,123456,...]
void taint_mix(uintptr_t shad_ptr, uint64_t dest, uint64_t src1, uint64_t src2, uint64_t size);

void taint_delete(uintptr_t shad_ptr, uint64_t dest, uint64_t size);

// Only generate when signed and dest_size > src_size.
// Otherwise it should just be a copy.
void taint_sext(uintptr_t shad_ptr, uint64_t dest, uint64_t dest_size, uint64_t src, uint64_t src_size);

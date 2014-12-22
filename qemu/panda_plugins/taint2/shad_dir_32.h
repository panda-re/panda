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

#ifndef __SHAD_DIR_32_H
#define __SHAD_DIR_32_H

#include "label_set.h"
#include "shad_dir.h"

// the top-level directory is an array of pointers to page tables
typedef struct SdDir32 {
  uint32_t num_dir_bits;
  uint32_t num_table_bits;
  uint32_t num_page_bits;
  uint32_t dir_size;
  uint32_t table_size;
  uint32_t page_size;
  // mask used to extract dir, table or page bits
  uint32_t dir_mask;
  uint32_t table_mask;
  uint32_t page_mask;
  // shift right this many bits to get dir index/offset
  uint32_t dir_shift;
  // array of pointers to page tables
  SdTable **table;
  // count number of label sets in the shadow mem
  int32_t num_non_empty;
} SdDir32;







/*
  creates initial, empty page directory.
  this is a mapping from addresses, which are unsigned integers of width
  (i.e. number of bytes) addr_size, to pointers to labelsets.
  top num_dir_bits of addr are the directory index
  next num_table_bits of addr are table index
  bottom num_page_bits are the page index
*/
SdDir32 *shad_dir_new_32(uint32_t num_dir_bits, uint32_t num_table_bits, uint32_t num_page_bits);


/*
  iterates over every entry in every page in shad_dir.
  calls app on every (addr, labelset) pair within every page
  app should return 0 if iteration is to continue.
  "stuff2" is a ptr to something the app fn needs
*/
void shad_dir_iter_32
     (SdDir32 *shad_dir,
      int (*app)(uint32_t addr, LabelSetP labelset, void *stuff1),
      void *stuff2);

// returns the number of addr to labelset mappings
uint32_t shad_dir_occ_32(SdDir32 *shad_dir);

// release all memory associated with this shad_dir
void shad_dir_free_32(SdDir32 *shad_dir);
int shad_dir_free_aux_32(uint32_t pa, SdPage *page, void *stuff);

/*
  add this mapping from addr to ls_new
  if a prior mapping exists, remove it first
  labelset is *not* copied.  We copy its slots.
*/
/*inline*/ void shad_dir_add_32(SdDir32 *shad_dir, uint32_t addr, LabelSetP ls_new);

// remove this mapping from addr to labelset
/*inline*/ void shad_dir_remove_32(SdDir32 *shad_dir, uint32_t addr);

// Return TRUE if this addr has a labelset (possibly empty), FALSE otherwise
/*inline*/ uint32_t shad_dir_mem_32(SdDir32 *shad_dir, uint32_t addr);

// Returns pointer to labelset associated with this address.
// Returns NULL if none
/*inline*/ LabelSetP shad_dir_find_32(SdDir32 *shad_dir, uint32_t addr);

#ifndef SD_TESTING
// marshall shad_dir to file
void shad_dir_save_32(void * /* QEMUFile * */ f, SdDir32 *shad_dir);

// unmarshall shad_dir from file
SdDir32 *shad_dir_load_32(void * /* QEMUFile * */ f);

#endif

#endif


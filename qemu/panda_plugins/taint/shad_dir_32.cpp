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

  3-level directory->table->page map from addresses to labelsets.
  Accommodates 64-bit addresses

  1st level is a directory
  ... which points to 2nd level which is a table
  ... which points to a page


  The top num_dir_bits of the address indexes us into a directory of
  1<<num_dir_bits entries to obtain a pointer to a table.

  The next num_table_bits bits of the address indexes us into the table,
  which contains 1<<num_table_bits entries, to obtain a pointer to a page.

  The bottom num_page_bits of hte address indexes us into the page,
  which contains 1<<num_page_bits entires, obtain a pointer to a labelset.

  Thus, the width of the address, in bits, must equal
  num_bits_dir + num_bits_table + num_bits_page

  The type of the address is a macro ADDR_TYPE.  Thus, it is a parameter.
  This file is used to create directories for different width addresses.


  The contract wrt label sets.
  Add.
  When a labelset is added to the shadow memory dir, we store a copy, created via
  labelset_copy (whcih increments reference count).

  Delete.
  When a labelset is removed from the shadow memory, we always destroy the copy
  with a call to labelset_free (which decrements reference count and possible triggers
  call to free).

  Find.
  When a labelset is returned by shad_dir_find..(), we return a copy, created via
  labelset_copy (to increment reference count).
  So don't forget to call labelset_free on it when you are done with it.

 */


#include <stdint.h>
#include "my_bool.h"
#include "my_mem.h"
#include "label_set.h"
#include "shad_dir_32.h"
#include "bitvector_label_set.cpp"

// create a new table
static SdTable *__shad_dir_table_new_32(SdDir32 *shad_dir) {
  SdTable *table = (SdTable *) my_calloc(1, sizeof(SdTable), poolid_shad_dir);
  table->page = (SdPage **) my_calloc(shad_dir->table_size, sizeof(SdPage *), poolid_shad_dir);
  table->num_non_empty = 0;
  return table;
}

static void __shad_dir_table_free_32(SdDir32 *shad_dir, SdTable *table) {
  if (shad_dir == NULL || table == NULL) return;
  assert (table->num_non_empty == 0);
  my_free(table->page, sizeof(SdPage *) * shad_dir->table_size, poolid_shad_dir);
  my_free(table, sizeof(SdTable), poolid_shad_dir);
}

static SdPage *__shad_dir_page_new_32(SdDir32 *shad_dir) {
  SdPage *page = (SdPage *) my_calloc(1, sizeof(SdPage), poolid_shad_dir);
  page->labels = (LabelSet **) my_calloc(shad_dir->page_size, sizeof(LabelSet *), poolid_shad_dir);
  page->num_non_empty = 0;
  return page;
}

static void __shad_dir_page_free_32(SdDir32 *shad_dir, SdPage *page) {
  if (shad_dir == NULL || page == NULL) return;
  assert (page->num_non_empty == 0);
  my_free(page->labels, sizeof(LabelSet *) * shad_dir->page_size, poolid_shad_dir);
  my_free(page, sizeof(SdPage), poolid_shad_dir);
}


/*
  creates initial, empty page directory.
  this is a mapping from addresses, which are unsigned integers of width
  (i.e. number of bytes) addr_size, to pointers to labelsets.
  top num_dir_bits of addr are the directory index
  next num_table_bits of addr are table index
  bottom num_page_bits are the page index
*/
SdDir32 *shad_dir_new_32
     (uint32_t num_dir_bits,
      uint32_t num_table_bits,
      uint32_t num_page_bits) {
  assert (num_dir_bits < 32 && num_table_bits < 32 && num_page_bits < 32);
  SdDir32 *shad_dir = (SdDir32 *) my_calloc(1, sizeof(SdDir32), poolid_shad_dir);
  shad_dir->num_dir_bits = num_dir_bits;
  shad_dir->num_table_bits = num_table_bits;
  shad_dir->num_page_bits = num_page_bits;
  assert (32 == num_dir_bits + num_table_bits + num_page_bits);
  shad_dir->dir_size = 1 << num_dir_bits;
  shad_dir->table_size = 1 << num_table_bits;
  shad_dir->page_size = 1 << num_page_bits;
  // mask to extract dir bits
  shad_dir->dir_shift = num_table_bits + num_page_bits;
  shad_dir->table_mask = ((1<<num_table_bits)-1) << num_page_bits;
  shad_dir->page_mask = (1<<num_page_bits)-1;
  shad_dir->dir_mask = ((1<<num_dir_bits)-1) << (shad_dir->dir_shift);
  shad_dir->table = (SdTable **) my_calloc(shad_dir->dir_size, sizeof(SdTable *),
					   poolid_shad_dir);
  shad_dir->num_non_empty = 0;
  return shad_dir;
}


/*
  macro to iterate over shadow memory pages.
  at the point "do_this" text gets inserted, the following useful
  iteration variables are defined
  "table" points to the SdTable for the current page
  "page" points to the SdPage for the current page
  "page_base_addr" is the guest physical address of the page for the current page
  "label_set_array" points to the array of ptrs to label sets for this page
*/

#define SD_PAGE_ITER(do_this, do_this_after_loop1, do_this_after_loop2)	\
{						 \
  /* iterate over entries in the directory */    \
  unsigned int di;			         \
  for (di=0; di<shad_dir->dir_size; di++) {	 \
    SdTable *table1 = shad_dir->table[di];       \
    if (table1 == NULL) continue;	         \
    unsigned int ti;                             \
    /* iterate over table entries */		 \
    for (ti=0; ti<shad_dir->table_size; ti++) {  \
      SdPage *page = table1->page[ti];	         \
      if (page == NULL) continue;                \
      uint32_t page_base_addr =					          \
        (di << shad_dir->dir_shift) | (ti << (shad_dir->num_page_bits));  \
      LabelSet **label_set_array = page->labels;                          \
      do_this;								  \
    } 		           \
    do_this_after_loop1    \
  }                        \
  do_this_after_loop2      \
}

/*
  Iterates over pages of labelsets in shadow memory.
  Applies app(pa, page), where pa is base address of the page in guest
  physical memory and "page" is a pointer to the SdPage struct for that
  shadow page.
  "stuff2" is a ptr to something the app fn needs
*/
static void __shad_dir_page_iter_32
     (SdDir32 *shad_dir,
      int (*app)(uint32_t pa, SdPage *page, void *stuff1),
      void *stuff2) {
  SD_PAGE_ITER(
	  { int iter_finished;
	    iter_finished =
	      app(page_base_addr, page, stuff2);
	    if (iter_finished != 0) return; } ,
	  SD_DO_NOTHING,
	  SD_DO_NOTHING
	   )
}


/*
  iterates over every entry in every page in shad_dir.
  calls app on every (addr, labelset) pair within every page
  app should return 0 if iteration is to continue.
  "stuff2" is a ptr to something the app fn needs
*/
void shad_dir_iter_32
     (SdDir32 *shad_dir,
      int (*app)(uint32_t addr, LabelSet *labels, void *stuff1),
      void *stuff2) {
  SD_PAGE_ITER(
	  { int iter_finished;
	    unsigned int ai;
	    for (ai=0; ai<shad_dir->page_size; ai++) {
	      uint32_t addr;
	      addr = page_base_addr | ai;
	      LabelSet *ls = label_set_array[ai];
	      iter_finished = 0;
	      if (ls != NULL)
		iter_finished = app(addr, ls, stuff2);
	      if (iter_finished != 0) return;
	    } },
	  SD_DO_NOTHING,
	  SD_DO_NOTHING
	  )
}


// returns the number of addr to labelset mappings
uint32_t shad_dir_occ_32(SdDir32 *shad_dir) {
  uint32_t occ = 0;
  SD_PAGE_ITER(
	       {occ += page->num_non_empty;},
	  SD_DO_NOTHING,
	  SD_DO_NOTHING
         )
  return occ;
}


int shad_dir_free_aux_32(uint32_t pa, SdPage *page, void *stuff) {
  uint32_t i;
  SdDir32 *shad_dir = (SdDir32 *) stuff;
  for (i=0; i<shad_dir->page_size; i++) {
    labelset_free(page->labels[i]);
  }
  my_free(page->labels, sizeof(LabelSet **) * shad_dir->page_size, poolid_shad_dir);
  return 0;
}


// release all memory associated with this shad pages
void shad_dir_free_32(SdDir32 *shad_dir) {
  SD_PAGE_ITER(
	       // free labelset associated with each addr in this page
	       {
		 uint32_t i;
		 for (i=0; i<shad_dir->page_size; i++) {
		   labelset_free(page->labels[i]);
		 }
                 page->num_non_empty = 0;
		 __shad_dir_page_free_32(shad_dir, page);
	       },
	       // free the table
	       {
		 table1->num_non_empty = 0;
		 __shad_dir_table_free_32(shad_dir, table1);
	       },
	       SD_DO_NOTHING
	       );
  my_free(shad_dir->table, shad_dir->dir_size * sizeof(SdTable *), poolid_shad_dir);
  my_free(shad_dir, sizeof (SdDir32), poolid_shad_dir);
}



/*
  retrieve labelset for addr.
  On success, ls points to that labelset after this macro.
  On fails, we specify the various actions to take.
  no_table_action: what to do if there's no page table
  no_page_action: what to do if there's no page
  no_labelset_action: what to do if there's no label set for this address
  After this macro, the following useful things exist
  table: points to the SdTable for this addr
  page: points to the SdPage for this addr
  ls: points to the labelset for this addr (might be NULL)
*/

// 32-bit addresses
#define SD_GET_LABELSET_32(addr, no_table_action, no_page_action, no_labelset_action) \
  uint32_t di = addr >> shad_dir->dir_shift; \
  SdTable *table = shad_dir->table[di];      \
  if (table == NULL) { no_table_action ; }   \
  uint32_t ti = (addr & shad_dir->table_mask) >> shad_dir->num_page_bits; \
  SdPage *page = table->page[ti];					  \
  if (page == NULL) { no_page_action ; }	  \
  LabelSet **label_set_array = page->labels;      \
  uint32_t offset = (addr & shad_dir->page_mask); \
  LabelSet *ls = label_set_array[offset];         \
  if (ls == NULL) { no_labelset_action ; }


// add table to the directory
static SdTable *__shad_dir_add_table_to_dir_32(SdDir32 *shad_dir, uint32_t di) {
  SdTable *table = __shad_dir_table_new_32(shad_dir);
  shad_dir->table[di] = table;
  shad_dir->num_non_empty++;
  return table;
}


static SdPage *__shad_dir_add_page_to_table_32(SdDir32 *shad_dir, SdTable *table, uint32_t pi) {
  SdPage *page = __shad_dir_page_new_32(shad_dir);
  table->page[pi] = page;
  table->num_non_empty ++;
  return page;
}


/*
  add this mapping from addr to ls_new
  if a prior mapping exists, remove it first
  labelset is *not* copied.  We copy its slots.
*/
void shad_dir_add_32(SdDir32 *shad_dir, uint32_t addr, LabelSet *ls_new) {
  // get ls, the labelset currently associated with this addr
  SD_GET_LABELSET_32(
    addr,
    table = __shad_dir_add_table_to_dir_32(shad_dir, di),
    page = __shad_dir_add_page_to_table_32(shad_dir, table, ti),
    SD_DO_NOTHING
  )
  if (ls == NULL) {
    // nothing there.
    // we are adding an addr -> label_set mapping
    page->num_non_empty++;
  }
  // discard copy of previous labelset associated with addr
  labelset_free(ls);
  // store copy of ls_new in shad_dir, associated with addr
  LabelSet *ls_new_copy = labelset_copy(ls_new);
  label_set_array[offset] = ls_new_copy;
}


// remove this mapping from addr to labelset
void shad_dir_remove_32(SdDir32 *shad_dir, uint32_t addr) {
  // get ls, the labelset currently associated with addr
  SD_GET_LABELSET_32(
    addr,
    return,
    return,
    return)
  if (ls != 0) {
    // we are removing an addr -> label_set mapping
    page->num_non_empty --;
  }
  // discard copy of previous labelset associated with addr
  labelset_free(ls);
  page->labels[offset] = NULL;
  assert (page->num_non_empty >= 0);
  if (page->num_non_empty == 0) {
    // page empty -- release it
    __shad_dir_page_free_32(shad_dir, page);
    table->page[ti] = NULL;
    table->num_non_empty--;
    assert(table->num_non_empty >= 0);
    if (table->num_non_empty == 0) {
      // table empty -- release it
      __shad_dir_table_free_32(shad_dir, table);
      shad_dir->table[di] = NULL;
      shad_dir->num_non_empty--;
      assert (shad_dir->num_non_empty >= 0);
    }
  }
}


// Return TRUE if this addr has a labelset (possibly empty), FALSE otherwise
uint32_t shad_dir_mem_32(SdDir32 *shad_dir, uint32_t addr) {
  SD_GET_LABELSET_32(
    addr,
    return FALSE,
    return FALSE,
    return FALSE
  )
  return TRUE;
}


// Returns pointer to labelset associated with this address.
// Returns NULL if none
LabelSet *shad_dir_find_32(SdDir32 *shad_dir, uint32_t addr) {
  // get ls, the labelset currently associated with addr
  SD_GET_LABELSET_32(
    addr,
    return NULL,
    return NULL,
    return NULL
  )
  if (ls == NULL) {
    return NULL;
  }
  LabelSet *ls_copy = labelset_copy(ls);
  return ls_copy;
}


#define SD_TESTING
#ifndef SD_TESTING

// this is where all the qemu_put and qemu_get come from
extern "C" {
#include "hw/hw.h"
}

int shad_dir_save_aux_32(uint32_t addr, LabelSet *ls, void *f) {
  qemu_put_be32(f, addr);
  labelset_save(f, ls);
  return 0;
}

// marshall shad_dir to file
void shad_dir_save_32(void * /* QEMUFile * */ f, SdDir32 *shad_dir) {
  qemu_put_be32(f, shad_dir->num_dir_bits);
  qemu_put_be32(f, shad_dir->num_table_bits);
  qemu_put_be32(f, shad_dir->num_page_bits);
  uint32_t occ = shad_dir_occ_32(shad_dir);
  qemu_put_be32(f, occ);
  shad_dir_iter_32(shad_dir, shad_dir_save_aux_32, f);
}


// unmarshall shad_dir from file
SdDir32 *shad_dir_load_32(void * /* QEMUFile * */ f) {
  uint32_t num_dir_bits = qemu_get_be32(f);
  uint32_t num_table_bits = qemu_get_be32(f);
  uint32_t num_page_bits = qemu_get_be32(f);
  SdDir32 *shad_dir =
    shad_dir_new_32(num_dir_bits, num_table_bits, num_page_bits);
  uint32_t occ = qemu_get_be32(f);
  int i;
  for (i=0; i<occ; i++) {
    uint32_t addr = qemu_get_be32(f);
    LabelSet *ls = labelset_load(f);
    shad_dir_add_32(shad_dir, addr, ls);
  }
  return shad_dir;
}

#endif

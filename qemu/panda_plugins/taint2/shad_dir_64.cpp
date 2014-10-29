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
  Same as shad_dir_32.c, mostly.

  5-level map from addresses to labelsets.
  Accommodates 64-bit addresses

  1st level is a directory
  ... which points to 2nd level which is a table
  ... which points to 3rd level, which is another table
  ... which points to 4th level, which is another table
  ... which points to a page

 */

#include <stdint.h>
#include "my_bool.h"
#include "my_mem.h"
#include "label_set.h"
#include "shad_dir_64.h"
#include "bitvector_label_set.cpp"

// 64-bit addresses
// create a new table
// if table_table==1 then this is a table of tables,
// else it is a table of pages
static SdTable *__shad_dir_table_new_64(SdDir64 *shad_dir, uint8_t table_table) {
  SdTable *table = (SdTable *) my_calloc(1, sizeof(SdTable), poolid_shad_dir);
  if (table_table == 1) {
    table->table = (SdTable **) my_calloc(shad_dir->table_size, sizeof(SdTable *), poolid_shad_dir);
  }
  else {
    table->page = (SdPage **) my_calloc(shad_dir->table_size, sizeof(SdPage *), poolid_shad_dir);
  }
  table->num_non_empty = 0;
  return table;
}


static void __shad_dir_table_free_64(SdDir64 *shad_dir, SdTable *table) {
  assert (table->num_non_empty == 0);
  if (table->table != NULL) {
    my_free(table->table, sizeof(SdTable *) * shad_dir->table_size, poolid_shad_dir);
  }
  if (table->page != NULL) {
    my_free(table->page, sizeof(SdPage *) * shad_dir->table_size, poolid_shad_dir);
  }

  my_free(table, sizeof(SdTable), poolid_shad_dir);
}

static SdPage *__shad_dir_page_new_64(SdDir64 *shad_dir) {
  SdPage *page = (SdPage *) my_calloc(1, sizeof(SdPage), poolid_shad_dir);
  page->labels = (LabelSet **) my_calloc(shad_dir->page_size, sizeof(LabelSet *), poolid_shad_dir);
  page->num_non_empty = 0;
  return page;
}

static void __shad_dir_page_free_64(SdDir64 *shad_dir, SdPage *page) {
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
SdDir64 *shad_dir_new_64
     (uint32_t num_dir_bits,
      uint32_t num_table_bits,
      uint32_t num_page_bits) {
  assert (num_dir_bits < 32 && num_table_bits < 32 && num_page_bits < 32);
  SdDir64 *shad_dir = (SdDir64 *) my_calloc(1, sizeof(SdDir64), poolid_shad_dir);
  shad_dir->num_dir_bits = num_dir_bits;
  shad_dir->num_table_bits = num_table_bits;
  shad_dir->num_page_bits = num_page_bits;
  assert (64 == num_dir_bits + 3*num_table_bits + num_page_bits);
  shad_dir->dir_size = 1 << num_dir_bits;
  shad_dir->table_size = 1 << num_table_bits;
  shad_dir->page_size = 1 << num_page_bits;
  // mask to extract dir bits
  shad_dir->dir_shift = 3 * num_table_bits + num_page_bits;
  shad_dir->table1_mask = ((uint64_t) ((1<<num_table_bits)-1)) << (2 * num_table_bits + num_page_bits);
  shad_dir->table2_mask = ((uint64_t) ((1<<num_table_bits)-1)) << (num_table_bits + num_page_bits);
  shad_dir->table3_mask = ((uint64_t) ((1<<num_table_bits)-1)) << num_page_bits;
  shad_dir->page_mask = (uint64_t) ((1<<num_page_bits)-1);
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
/* 64-bit addresses */				   \
#define SD_PAGE_ITER(do_this) \
{						   \
  /* iterate over entries in the directory */      \
  unsigned int di;				   \
  for (di=0; di<shad_dir->dir_size; di++) {	   \
    SdTable *table1 = shad_dir->table[di];         \
    if (table1 == NULL) continue;	           \
    unsigned int t1i,t2i,t3i;		           \
    /* iterate over tables in first level */		 \
    for (t1i=0; t1i<shad_dir->table_size; t1i++) {       \
      SdTable *table2 = table1->table[t1i];              \
      if (table2 == NULL) continue;                      \
      for (t2i=0; t2i<shad_dir->table_size; t2i++) {     \
	/* iterate over tables in second level */	 \
        SdTable *table3 = table2->table[t2i];	         \
        if (table3 == NULL) continue;                    \
        for (t3i=0; t3i<shad_dir->table_size; t3i++) {   \
	  /* iterate over tables in third level */	 \
          SdPage *page = table3->page[t3i];              \
          if (page == NULL) continue;                    \
          uint64_t page_base_addr = di;                                        \
          page_base_addr = (page_base_addr << shad_dir->num_table_bits) | t1i;	\
          page_base_addr = (page_base_addr << shad_dir->num_table_bits) | t2i;	\
          page_base_addr = (page_base_addr << shad_dir->num_table_bits) | t3i;	\
          page_base_addr = page_base_addr << shad_dir->num_page_bits;           \
          LabelSet **label_set_array = page->labels;                            \
          do_this ;         \
        }                   \
      }                     \
    }                       \
  }                         \
}


/*
  Iterates over pages of labelsets in shadow memory.
  Applies app(pa, page), where pa is base address of the page in guest
  physical memory and "page" is a pointer to the SdPage struct for that
  shadow page.
  "stuff2" is a ptr to something the app fn needs
*/
static void __shad_dir_page_iter_64
     (SdDir64 *shad_dir,
      int (*app)(uint64_t pa, SdPage *page, void *stuff1),
      void *stuff2) {
  SD_PAGE_ITER(
	  { int iter_finished;
	    iter_finished =
	      app(page_base_addr, page, stuff2);
	    if (iter_finished != 0) return; }
	   )
}


/*
  iterates over every entry in every page in shad_dir.
  calls app on every (addr, labelset) pair within every page
  app should return 0 if iteration is to continue.
  "stuff2" is a ptr to something the app fn needs
*/
void shad_dir_iter_64
     (SdDir64 *shad_dir,
      int (*app)(uint64_t addr, LabelSet *labels, void *stuff1),
      void *stuff2) {
  SD_PAGE_ITER(
	  { int iter_finished;
	    unsigned int ai;
	    for (ai=0; ai<shad_dir->page_size; ai++) {
	      uint64_t addr;
	      addr = page_base_addr | ai;
	      LabelSet *ls = label_set_array[ai];
	      iter_finished = 0;
	      if (ls != NULL)
		iter_finished = app(addr, ls, stuff2);
	      if (iter_finished != 0) return;
	    } }
	  )
}


// returns the number of addr to labelset mappings
uint32_t shad_dir_occ_64(SdDir64 *shad_dir) {
  uint32_t occ = 0;
  SD_PAGE_ITER(
	  occ += page->num_non_empty;
         )
  return occ;
}


int shad_dir_free_aux_64(uint64_t pa, SdPage *page, void *stuff) {
  uint32_t i;
  SdDir64 *shad_dir = (SdDir64 *) stuff;
  for (i=0; i<shad_dir->page_size; i++) {
    labelset_free(page->labels[i]);
  }
  my_free(page->labels, sizeof(LabelSet **) * shad_dir->page_size, poolid_shad_dir);
  return 0;
}


// release all memory associated with this shad pages
void shad_dir_free_64(SdDir64 *shad_dir) {
  __shad_dir_page_iter_64
    (shad_dir, shad_dir_free_aux_64, shad_dir);
  my_free(shad_dir->table, shad_dir->dir_size * sizeof(SdTable *), poolid_shad_dir);
  my_free(shad_dir, sizeof (SdDir64), poolid_shad_dir);
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


#define SD_GET_LABELSET_64(addr, no_table1_action, no_table2_action, no_table3_action, no_page_action, no_labelset_action)			       \
  uint32_t di = addr >> shad_dir->dir_shift;  \
  SdTable *table1 = shad_dir->table[di];      \
  if (table1 == NULL) { no_table1_action ; }  \
  uint32_t sh = shad_dir->num_table_bits * 2 + shad_dir->num_page_bits; \
  uint32_t t1i = (addr & shad_dir->table1_mask) >> sh;    \
  SdTable *table2 = table1->table[t1i];     \
  if (table2 == NULL) {	no_table2_action ; }  \
  sh -= shad_dir->num_table_bits; \
  uint32_t t2i = (addr & shad_dir->table2_mask) >> sh; 	\
  SdTable *table3 = table2->table[t2i];     \
  if (table3 == NULL) {	no_table3_action ; }  \
  sh -= shad_dir->num_table_bits; \
  uint32_t t3i = (addr & shad_dir->table3_mask) >> sh; 	\
  SdPage *page = table3->page[t3i];		  \
  if (page == NULL) { no_page_action ; }	  \
  LabelSet **label_set_array = page->labels;      \
  uint32_t offset = (addr & shad_dir->page_mask); \
  LabelSet *ls = label_set_array[offset];         \
  if (ls == NULL) { no_labelset_action ; }



// add table to the directory
static SdTable *__shad_dir_add_table_to_dir_64(SdDir64 *shad_dir, uint32_t di) {
  SdTable *table = __shad_dir_table_new_64(shad_dir, 1);
  shad_dir->table[di] = table;
  shad_dir->num_non_empty++;
  return table;
}



// add either a table of tables or a table of pages.
// table_table==0 means add a table of tables. else add a table of pages
static SdTable *__shad_dir_add_something_to_table_64
  (SdDir64 *shad_dir, SdTable *table_last, uint32_t ti, uint8_t table_table) {
  SdTable *table = __shad_dir_table_new_64(shad_dir, table_table);
  table_last->table[ti] = table;
  table_last->num_non_empty++;
  return table;
}



static SdPage *__shad_dir_add_page_to_table_64(SdDir64 *shad_dir, SdTable *table, uint32_t pi) {
  SdPage *page = __shad_dir_page_new_64(shad_dir);
  table->page[pi] = page;
  table->num_non_empty ++;
  return page;
}



// faking out the macro to tolerate comma
//#define TABLETI table, ti





/*
  add this mapping from addr to ls_new
  if a prior mapping exists, remove it first
  labelset is *not* copied.  We copy its slots.
*/
void shad_dir_add_64(SdDir64 *shad_dir, uint64_t addr, LabelSet *ls_new) {
  // get ls, the labelset currently associated with this addr
  SD_GET_LABELSET_64(
    addr,
    table1 = __shad_dir_add_table_to_dir_64(shad_dir, di),
    table2 = __shad_dir_add_something_to_table_64(shad_dir, table1, t1i, 1),
    table3 = __shad_dir_add_something_to_table_64(shad_dir, table2, t2i, 0),
    page = __shad_dir_add_page_to_table_64(shad_dir, table3, t3i),
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
void shad_dir_remove_64(SdDir64 *shad_dir, uint64_t addr) {
  // get ls, the labelset currently associated with addr
  SD_GET_LABELSET_64(
    addr,
    return,
    return,
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
    __shad_dir_page_free_64(shad_dir, page);
    table3->page[t3i] = NULL;
    table3->num_non_empty--;
    assert (table3->num_non_empty >= 0);
    if (table3->num_non_empty == 0) {
      // level 3 table empty -- release it
      __shad_dir_table_free_64(shad_dir, table3);
      table2->table[t2i] = NULL;
      table2->num_non_empty--;
      assert (table2->num_non_empty >= 0);
      if (table2->num_non_empty == 0) {
	// level 2 table empty -- release it
	__shad_dir_table_free_64(shad_dir, table2);
	table1->table[t1i] = NULL;
	table1->num_non_empty--;
	assert (table1->num_non_empty >= 0);
	if (table1->num_non_empty == 0) {
	  // level 1 table empty -- release it
	  __shad_dir_table_free_64(shad_dir, table1);
	  shad_dir->table[di] = NULL;
	  shad_dir->num_non_empty--;
	  assert (shad_dir->num_non_empty >= 0);
	}
      }
    }
  }
}


// Return TRUE if this addr has a labelset (possibly empty), FALSE otherwise
uint32_t shad_dir_mem_64(SdDir64 *shad_dir, uint64_t addr) {
  // 64-bit addrs
  SD_GET_LABELSET_64(
    addr,
    return FALSE,
    return FALSE,
    return FALSE,
    return FALSE,
    return FALSE
  )
  return TRUE;
}


// Returns pointer to labelset associated with this address.
// Returns NULL if none
LabelSet *shad_dir_find_64(SdDir64 *shad_dir, uint64_t addr) {
  // get ls, the labelset currently associated with addr
  SD_GET_LABELSET_64(
    addr,
    return NULL,
    return NULL,
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


int shad_dir_save_aux_64(uint64_t addr, LabelSet *ls, void *f) {
  qemu_put_be64(f, addr);
  labelset_save(f, ls);
  return 0;
}

// marshall shad_dir to file
void shad_dir_save_64(void * /* QEMUFile * */ f, SdDir64 *shad_dir) {
  qemu_put_be32(f, shad_dir->num_dir_bits);
  qemu_put_be32(f, shad_dir->num_table_bits);
  qemu_put_be32(f, shad_dir->num_page_bits);
  uint32_t occ = shad_dir_occ_64(shad_dir);
  qemu_put_be32(f, occ);
  shad_dir_iter_64(shad_dir, shad_dir_save_aux_64, f);
}


// unmarshall shad_dir from file
SdDir64 *shad_dir_load_64(void * /* QEMUFile * */ f) {
  uint32_t num_dir_bits = qemu_get_be32(f);
  uint32_t num_table_bits = qemu_get_be32(f);
  uint32_t num_page_bits = qemu_get_be32(f);
  SdDir64 *shad_dir =
    shad_dir_new_64(num_dir_bits, num_table_bits, num_page_bits);
  uint32_t occ = qemu_get_be32(f);
  int i;
  for (i=0; i<occ; i++) {
    uint64_t addr = qemu_get_be64(f);
    LabelSet *ls = labelset_load(f);
    shad_dir_add_64(shad_dir, addr, ls);
  }
  return shad_dir;
}

#endif

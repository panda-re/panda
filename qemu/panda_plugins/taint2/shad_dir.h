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

#ifndef __SHAD_DIR_H_
#define __SHAD_DIR_H_

// struct for a page
typedef struct sd_page_struct {
  // array of pointers to label sets, one for each offset within the page
  LabelSetP *labels;
  // count non-empty label sets in page
  int32_t num_non_empty;
} SdPage;


typedef struct sd_table_struct {
  // pointer to more tables
  struct sd_table_struct **table;
  // pointer to pages
  SdPage **page;
  // count non-empty pages in this table
  int32_t num_non_empty;
} SdTable;

#define SD_DO_NOTHING {do {} while (0);}
#endif

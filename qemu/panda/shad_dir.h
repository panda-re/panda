#ifndef __SHAD_DIR_H_
#define __SHAD_DIR_H_


// struct for a page
typedef struct sd_page_struct {
  // array of pointers to label sets, one for each offset within the page
  LabelSet **labels;    
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


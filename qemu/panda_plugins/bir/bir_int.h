#ifndef __BIR_INT_H_
#define __BIR_INT_H_

#include "index.h"


void *invert_c(void *index);
void *new_indexer_c(uint32_t min_n_gram, uint32_t max_n_gram, uint32_t passage_len_bytes) ;
void index_this_passage_c(void *indexer, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) ;
void marshall_invindex_c(void *invindex, char *file_pfx);                                                                  
void marshall_index_c(void *vpindex, char *file_pfx);
void *indexer_get_index_c(void *vpindexer);
void indexer_set_passage_len_bytes_c(void *vpindexer, uint32_t passage_len_bytes) ;
void *unmarshall_preprocessed_scores_c (char *filename_pfx);
void query_with_passage_c (void *vppassage, void *vppps, uint32_t *ind, float *score);

#endif

#ifndef __BIR_INT_H_
#define __BIR_INT_H_


void index_this_passage_c(void *vpindc, void *vpindex, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) ;

void *invert_c(void *vpindc, void *vpindex) ;

void marshall_index_common_c(void *vpindc);

void marshall_index_c(void *vpindc, void *vpindex, char *file_pfx);

void marshall_invindex_c(void *vpindc, void *vpinv, char *file_pfx) ;

void *unmarshall_preprocessed_scores_c (char *filename_pfx);

void query_with_passage_c (void *vpindc, void *vppassage, void *vppps, uint32_t *ind, float *score);

void *new_index_common_c(char *filename_prefix, uint32_t min_n_gram, uint32_t max_n_gram, uint32_t passage_len_bytes) ;

void *new_index_c(void) ;

void index_common_set_passage_len_bytes_c(void *vpindc, uint32_t passage_len_bytes);


#endif

Plugin: bir
===========

Summary
-------

Arguments
---------

    std::string pfx(panda_parse_string(args, "pfx", "unk"));
    max_row_length = panda_parse_uint32(args, "max_row_length", 10000);
    pdice_prob = panda_parse_double(args, "pdice", 1.0);
    pc_start = panda_parse_ulong(args, "pc_start", 0);
    pc_end = panda_parse_ulong(args, "pc_end", (target_ulong)~0UL);
    ignore_bb_len = panda_parse_bool(args, "ignore_bb_len");
    const char *output_filename = panda_parse_string(args, "output", "");

Dependencies
------------

None.

APIs and Callbacks
------------------

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



Example
-------


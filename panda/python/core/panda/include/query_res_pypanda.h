

typedef struct query_result {
    uint32_t num_labels;
    // ptrs to label set and c++ iterator 
    void *ls;
    void *it_end;
    void *it_curr;
    // taint compute number for this set
    uint32_t tcn;
    // controlled bit mask
    uint8_t cb_mask;
} QueryResult;


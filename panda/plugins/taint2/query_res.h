#ifndef __QUERY_RES_H__
#define __QUERY_RES_H__


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.


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

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!


#endif

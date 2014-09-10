
extern "C" {
    
#include <stdio.h>
#include <assert.h>
    
}

#include "index.hpp"
#include<map>


Lexicon merge_lexicons(Lexicon &l1, Lexicon &l2) {
    Lexicon lm = Lexicon();
    assert (l1.n == l2.n);
    lm.n = l1.n;
    for ( auto &gram : l1.grams ) {
        lm.grams.insert(gram);
    }
    for ( auto &gram : l2.grams ) {
        lm.grams.insert(gram);
    }
    return lm;
}



std::map < Gram, uint32_t > merge_general_query(uint32_t n,
                                                InvIndex &inv_a, InvIndex &inv_b, 
                                                Lexicon &lex_merged) {
    // iterate over words in merged lexicon
    std::map < Gram, uint32_t > gc;
    for ( auto &gram : lex_merged.grams ) {
        uint32_t count = 0;
        // merge counts for inv_a and inv_b
        if ( inv_a.general_query[n].count(gram) != 0) {
            count += inv_a.general_query[n][gram];
            //            spit_gram_hex(gram, n);
            //            printf (" is in a\n");
        }
        if ( inv_b.general_query[n].count(gram) != 0) {
            count += inv_b.general_query[n][gram];
            //            spit_gram_hex(gram, n);
            //            printf (" is in b\n");
        }
        gc[gram] = count;
    }
    return gc;
}





static GramPsgCounts row;
static bool init_row = true;

// obtain row data for gram from inv_for_row.
// then, copy that data into merged_row, fixing passage numbers
// passage_num_offset is what we have to add to every passage number
void merge_row(const Gram &gram, 
               uint32_t n,
               FILE *fp_for_row,
               InvIndex &inv_for_row,
               InvIndex &minv,
               GramPsgCounts &merged_row,
               uint32_t passage_num_offset) {
    //  printf ("merge_row gram = ");
    //  spit_string_hex(gram);
    //  printf ("\n");
    if (init_row) {
        init_row = false;
        row.size = 0;
        row.max_size = 10;
        row.counts = (CountPair *) malloc (sizeof(CountPair) * row.max_size);
    }
    if (inv_for_row.lexicon[n].grams.count(gram) != 0) {
        // this inv does have counts for this gram 
        // retrieve row.
        unmarshall_row_fp(fp_for_row, inv_for_row, n, gram, row);
        //    printf ("row len=%d\n", row.size);
        // make sure merged row big enough to accomodate this additional info
        resize_doc_word(merged_row, merged_row.size + row.size);
        int i;
        uint32_t ri = merged_row.size;
        for (i=0; i<row.size; i++) {
            CountPair *p = &(row.counts[i]);
            // passage ind wrt merge
            merged_row.counts[ri].passage_ind = p->passage_ind + passage_num_offset; 
            merged_row.counts[ri].count = p->count;
            ri ++;
        }
        merged_row.size += row.size;
    }
}


   
// these are the pfx for the two index files to be merged
// inv_a_pfx 
// inv_b_pfx
// and this is where they will get merged
// inv_merge_pfx
void merge_inv_indexes(char *inv_a_pfx, 
                       char *inv_b_pfx,
                       char *inv_merge_pfx) {
    char filename[65535];
    // loads all but gram -> array of psgid/count 
    // for both indices to be merged
    InvIndex inv_a = unmarshall_invindex_min(inv_a_pfx);
    InvIndex inv_b = unmarshall_invindex_min(inv_b_pfx);
    assert (inv_a.min_n_gram == inv_b.min_n_gram);
    assert (inv_a.max_n_gram == inv_b.max_n_gram);
    uint32_t min_n = inv_a.min_n_gram;
    uint32_t max_n = inv_a.max_n_gram;
    InvIndex minv = invindex_min_new(inv_merge_pfx, min_n, max_n, inv_a.passage_len_bytes);
    for (int n=min_n; n<=max_n; n++) {
        // merge lexicons for this gram
        minv.lexicon[n] = merge_lexicons(inv_a.lexicon[n], inv_b.lexicon[n]);
        // merge general query model
        minv.general_query[n] = merge_general_query(n, inv_a, inv_b, minv.lexicon[n]);
        // sum up total counts
        minv.total_count[n] = inv_a.total_count[n] + inv_b.total_count[n];
    }
    // merge filename_to_first_passage maps
    // just copy inv_a
    for ( auto &kvp : inv_a.filename_to_first_passage) {
        minv.filename_to_first_passage[kvp.first] = kvp.second;
    }
    // but for inv_b you need to correct passages numbers
    for ( auto &kvp : inv_b.filename_to_first_passage) {
        minv.filename_to_first_passage[kvp.first] = kvp.second + inv_a.num_passages;
    }
    // merge first_passage_to_filename maps
    // again, just copy inv_a
    for ( auto &kvp : inv_a.first_passage_to_filename) {
        minv.first_passage_to_filename[kvp.first] = kvp.second;
    }
    // but for inv_b, we need to correct passage numbers
    for ( auto &kvp : inv_b.first_passage_to_filename) {
        minv.first_passage_to_filename[kvp.first + inv_a.num_passages] = kvp.second;
    }
    /*
  // now merge passage lengths
  // note that passage lengths not same for each of the grams
  for (int n=min_n; n<=max_n; n++) {
    for ( auto &kvp : inv_a.passage_len[n] ) {
      minv.passage_len[n][kvp.first] = kvp.second;
    }
    // again, passage inds for b we increment by pm_inc, i.e., inv_a.num_passages  
    for ( auto &kvp : inv_b.passage_len[n] ) {
      minv.passage_len[n][kvp.first + pm_inc] = kvp.second;
    }
  }
    */
    minv.num_passages = inv_a.num_passages + inv_b.num_passages;
  // finally, merge the inv index of doc-count rows per word, one per n-gram
  // as well as the file pos inv-map, one per n-gram 
  GramPsgCounts row_merged;
  row_merged.size = 0;
  row_merged.max_size = 0;
  row_merged.counts = NULL;
  for (int n=min_n; n<=max_n; n++) {
    printf ("merging inv index for n=%d\n", n);
    // open first inv indices for read
    sprintf(filename, "%s.inv-%d", inv_a_pfx, n);
    FILE *fp_a = fopen(filename, "r");
    // open second inv index for read
    sprintf(filename, "%s.inv-%d", inv_b_pfx, n);
    FILE *fp_b = fopen(filename, "r");
    // open merged inv index for write
    sprintf(filename, "%s.inv-%d", inv_merge_pfx, n);
    FILE *fp_merge = fopen(filename, "w");
    printf ("merge: lexicon %d has occ = %d\n", n, minv.lexicon[n].grams.size());
    for ( auto &gram : minv.lexicon[n].grams ) {
        //        spit_gram_hex(gram, n);
        //        printf ("\n");
      // this is file pos for this row
      long pos = ftell(fp_merge);      
      //            printf ("pos = %d\n", pos);
      minv.map_dw[n][gram] = pos;
      // merge the rows from a and b
      row_merged.size = 0;
      //            printf ("merge a\n");
      merge_row(gram, n, fp_a, inv_a, minv, row_merged, 0);
      //            printf ("merged len is %d\n", row_merged.size);
      //            printf ("merge b\n");
      merge_row(gram, n, fp_b, inv_b, minv, row_merged, inv_a.num_passages);
      //            printf ("merged len is %d\n", row_merged.size);
      // finally, write merged row

      //            printf ("before writing row, pos = %d\n", ftell(fp_merge));
      marshall_row_fp(fp_merge, row_merged);
      //            printf ("after writing row, pos = %d\n", ftell(fp_merge));
    }      
  }

  


  // marshalls all but the actual inverted index of DocWords
  // note, this must be last since we need map_dw
  marshall_invindex_min(minv);

}



// 3 args
// pfx_a, pfx_b, and pfx_merge
// all three are filename prefix to an inverted index
// a & b correspond to a pair that are to be merged
// pfx_merge is where the merged inv index will be written to
int main (int argc, char **argv) {
  if (argc !=4) {
    printf ("usage: ind_pfx_1 ind_pfx_2 merge_pfx\n");
    exit(1);
  }
  char *pfx_a = argv[1];
  char *pfx_b = argv[2];
  char *pfx_merged = argv[3];
  merge_inv_indexes(pfx_a, pfx_b, pfx_merged);
}

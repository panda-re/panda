
extern "C"{
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

}

#include "index.hpp"

//#include <chrono>
#include <iostream>
#include <unordered_set>

uint32_t max_row_length=1000000;

extern "C" {
    void *invert_c(void *index);
    void *new_index_common_c(char *filename_prefix, uint32_t min_n_gram, uint32_t max_n_gram, uint32_t passage_len_bytes) ;
    void *new_index_c(void);
    void indc_set_passage_len_bytes_c(void *vpindc, uint32_t passage_len_bytes);
    void index_this_passage_c(void *indc, void *index, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) ;
    void marshall_invindex_c(void *invindex, char *file_pfx);                                                                  
    void marshall_index_c(void *vpindex, char *file_pfx);
    void *unmarshall_preprocessed_scores_c (char *filename_pfx);
    void query_with_passage_c (void *vppassage, void *vppps, uint32_t *ind, float *score);
}


   
IndexCommon *new_index_common(std::string pfx, 
                              uint32_t min_n_gram, uint32_t max_n_gram,
                              uint32_t passage_len_bytes) {
    IndexCommon *indc = new IndexCommon;  
    indc->filename_prefix = pfx;
    indc->min_n_gram = min_n_gram;
    indc->max_n_gram = max_n_gram;
    indc->passage_len_bytes = passage_len_bytes;
    indc->num_passages = 0;
    return indc;
}


void spit_gram_hex(const Gram gram, uint32_t n) {
    uint32_t i;
    printf ("(n=%d,", n);
    for (i=0; i<n; i++) {
        uint8_t *p = (uint8_t *) &(gram);
        printf ("%02x", *(p +i));
    }
    printf (")");
}


// returns the n bytes starting at begin of buf
// packed into a uint64_t with all other bytes
// in the uint64_t zeroed
// NB: first byte in gram is lowest-order byte in returned uint64_t
Gram gram64(uint8_t *buf, int n) {
    assert (n<=8);
    Gram g = ( *((uint64_t *) (buf))) & (0xffffffffffffffff >> (64 - n*8));
    return g;
}
  

// returns sub-gram starting at pos of len bytes
Gram gramsub(Gram g, uint32_t pos, uint32_t len) {
    uint64_t mask = (0xffffffffffffffff >> (64 - len * 8)) << (8 * pos);
    return (((uint64_t) g) & mask) >> (8 * pos);
}




void spit_passage_dist(PassageDist &pd) {
    if (pd.count.size() == 0) {
        return ;
    }
    printf ("PassageDist [\n");
    printf ("n=%d total=%d\n", pd.n, pd.total);
    // iterate over grams in passage for this n
    for ( auto &kvp : pd.count ) {
        Gram gram = kvp.first;
        uint32_t count = kvp.second;
        printf ("(%d,", count);
        spit_gram_hex(gram, pd.n);
        printf (") ");
    }
    printf ("\n");
    printf ("PassageDist ]\n");
}

  
void spit_passage(Passage &passage) {
    printf ("Passage [\n");
    printf ("uind=%d \n", passage.uind);
    // iterate over n
    for ( auto &kvp : passage.contents ) {
        printf ("n=%d\n", kvp.first);
        spit_passage_dist(kvp.second);
    }
    printf ("Passage ]\n");
}


 
void spit_lexicon(Lexicon &lexicon) {
    printf ("Lexicon %d [\n", lexicon.n);
    printf ("size=%d\n", (int) lexicon.grams.size());
    for ( auto &gram : lexicon.grams ) {    
        printf ("gram : ") ;
        spit_gram_hex(gram, lexicon.n);
        printf ("\n");
    }
    printf ("Lexicon ]\n");
}

void spit_uind_to_psgs(std::map < uint32_t, std::set < uint32_t > > &uind_to_psgs) {
    printf ("uind_to_psgs [\n");
    printf ("size=%d\n", uind_to_psgs.size());
    for ( auto &kvp : uind_to_psgs ) {
        uint32_t uind = kvp.first;
        printf ("uind = %d : ", uind);
        for ( auto &el : kvp.second ) {
            printf ("%d ", el);
        }
        printf ("\n");
    }
    printf ("uind_to_psgs ]\n");
}

void spit_string_to_uint32_map ( std::map < std::string, uint32_t > & su32m ) {
    printf ("su32m [\n");
    printf ("size=%d\n", su32m.size());
    for ( auto &kvp : su32m ) {
        printf ("%s -> %d\n", kvp.first.c_str(), kvp.second );
    }
    printf ("su32m ]\n");
}

void spit_uint32_to_string_map ( std::map < uint32_t, std::string > & u32sm ) {
    printf ("u32sm [\n");
    printf ("size=%d\n", u32sm.size());
    for ( auto &kvp : u32sm ) {
        printf ("%d -> %s\n", kvp.first, kvp.second.c_str() );
    }
    printf ("u32sm ]\n");
}
    

void spit_index_common(IndexCommon *indc) {
    printf ("min,max ngrams = (%d,%d)\n", indc->min_n_gram, indc->max_n_gram);
    printf ("passage_len_bytes = %d\n", indc->passage_len_bytes);
    printf ("%d passages\n", indc->num_passages);
    printf ("Lexicons [\n");
    uint32_t n;
    for (n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("\nlexicon n=%d\n", n);
        spit_lexicon(indc->lexicon[n]);
    }
    printf ("Lexicons ]\n");
    spit_uind_to_psgs(indc->uind_to_psgs);
    printf ("filename_to_first_passage [\n");
    spit_string_uint32_map(indc->filename_to_first_passage);
    printf ("filename_to_first_passage ]\n");
    printf ("first_passage_to_filename [\n");
    spit_uint32_string_map(indc->first_passage_to_filename);
    printf ("first_passage_to_filename ]\n");
}


void spit_index(Index *index) {
    printf ("Index [\n");
    printf ("binary_to_uind is %d entries\n", index->binary_to_uind.size());
    printf ("uind_to_passage [\n");
    printf ("size=%d\n", index->uind_to_passage.size());
    for ( auto &kvp : index->uind_to_passage ) {
        printf ("uind = %d\n", kvp.first);
        spit_passage(kvp.second);
    }
    printf ("uind_to_passage ]\n");
    printf ("passages [\n");
    printf ("size=%d\n", index->passages.size());
    // iterate over passages
    for ( auto &kvp : index->passages ) {
        printf ("%d -> %d\n", kvp.first, kvp.second);
    }
    printf ("passages ]\n");
    printf ("Index ]\n");
}



// collect n-gram distributions for passage.  length len.  may contain nulls
Passage index_passage (IndexCommon *indc, bool update,
                       uint8_t *binary_passage, uint32_t len,
                       uint32_t uind) {
    Passage passage;
    passage.uind = uind;
    for (uint32_t n=indc->min_n; n<=indc->max_n; n++) {
        PassageDist pd;
        pd.n = n;
        pd.total = 0;
        uint32_t i;
        for (i=0; i<=len-n; i++) {
            //  add / update count for n-gram starting at pos "start"
            Gram gram = gram64 (binary_passage+i, n);
            bool indexp = false;
            if (indc->lexicon[n].grams.find(gram) == indc->lexicon[n].grams.end()) {
                // gram is not in the lexicon
                if (update) {
                    // we are updating lexicon so add it
                    indc->lexicon[n].grams.insert(gram);
                    indexp = true;
                }
                else {
                    // ignoring this gram. indexp = false
                }
            }
            else {
                // gram is in the lexicon -- we'll index it
                indexp = true;
            }
            if (indexp) {
                // gram must be in the lexicon if we get here
                pd.count[gram] += 1;
            }
            pd.total += 1;
        }    
        passage.contents[n] = pd;
    }
    // printf ("finished indexing passage %d\n", passage_ind);
    return passage;
}


void spit_general_query(IndexCommon &indc, std::map < uint32_t, std::map < Gram, uint32_t > > &general_query ) {
    printf ("general_query [\n");
    for (uint32_t n=inv->min_n_gram; n<=inv->max_n_gram; n++) {
        printf ("n=%d\n", n);
        for ( auto &kvp : inv->general_query[n] ) {
            printf ("  ");
            spit_gram_hex(kvp.first, n);
            printf (" %d\n", kvp.second);
        }
    }
    printf ("general_query ]\n");
    printf ("InvIndex ]\n");
}


void spit_inv(InvIndex &inv) {
    //    spit_inv_min(inv);
    printf ("docs_with_word [\n");
    for (uint32_t n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        printf ("n=%d\n", n);
        for ( auto &kvp : inv.docs_with_word[n] ) {
            Gram gram = kvp.first;
            printf ("  gram : ") ;
            spit_gram_hex(gram, n);
            printf ("\n");
            printf ("    ");
            /*
              for ( auto &kvp2 : kvp.second ) {
              printf ("(c=%d, p=%s)", kvp2.second, inv.ind_to_passage_name[kvp2.first].c_str());
              }
            */
            printf ("\n");
        }
    }
    printf ("docs_with_word ]\n");
}


void marshall_lexicon(std::string filename, Lexicon &lexicon){ 
    FILE *fp = fopen ((char *) filename.c_str(), "w");
    uint32_t occ = lexicon.grams.size();
    WU(occ);
    WU(lexicon.n);
    for ( auto &gram : lexicon.grams ) {
        WU(gram);
    }
    fclose(fp);
}


void marshall_uint32_uint32_map(std::string filename, std::map < uint32_t, uint32_t > &uumap) {
    FILE *fp = fopen ((char *) filename.c_str(), "w");
    uint32_t occ = uumap.size();
    WU(occ);
    for ( auto &kvp : uumap ) {
        WU(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}


void marshall_gram_long_map(std::string filename, std::map < Gram, long > &glmap ) {
    FILE *fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = glmap.size();
    WU(occ);
    for ( auto &kvp : glmap ) {
        WU(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}



void marshall_gram_uint32_map(std::string filename, std::map < Gram, uint32_t > &gumap ) {
    FILE *fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = gumap.size();
    WU(occ);
    for ( auto &kvp : gumap ) {
        WU(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}


void marshall_string_uint32_map(std::string filename, std::map < std::string, uint32_t > &sumap ) {
    FILE *fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = sumap.size();
    WU(occ);
    for ( auto &kvp : sumap ) {
        WS(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}


void marshall_uint32_string_map(std::string filename, std::map < uint32_t, std::string > &usmap ) {
    FILE *fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = usmap.size();
    WU(occ);
    for ( auto &kvp : usmap ) {
        WU(kvp.first);
        WS(kvp.second);
    }
    fclose(fp);
}


Lexicon unmarshall_lexicon(std::string filename, uint32_t n) {
    FILE *fp = fopen ((char *) filename.c_str(), "r");
    uint32_t occ;
    RU(occ);
    Lexicon lexicon;
    RU(lexicon.n);
    lexicon.n = n;
    for (uint32_t i=0; i<occ; i++) {
        Gram gram;
        RU(gram);    
        lexicon.grams.insert(gram);
    }
    fclose(fp);
    return lexicon;
}


std::map < uint32_t, uint32_t > unmarshall_uint32_uint32_map(std::string filename) {
    FILE *fp = fopen ((char *)filename.c_str(), "r");
    uint32_t occ;
    RU(occ); 
    std::map < uint32_t, uint32_t > uumap;
    for (uint32_t i=0; i<occ; i++) {
        uint32_t key, val;
        RU(key);
        RU(val);
        uumap[key] = val;
    }
    fclose(fp);
    return uumap;
}


std::map < Gram, long > unmarshall_gram_long_map(std::string filename) {
    FILE *fp = fopen ((char *)filename.c_str(), "r");
    uint32_t occ;
    RU(occ); 
    printf ("occ = %d\n", occ);
    std::map < Gram, long > glmap;
    for (uint32_t i=0; i<occ; i++) {
        Gram g;
        RU(g);
        long val;
        RL(val);
        glmap[g] = val;
    }
    fclose(fp);
    return glmap;
}
			      

std::map < std::string, uint32_t > unmarshall_string_uint32_map(std::string filename) {
    FILE *fp = fopen ((char *)filename.c_str(), "r");
    uint32_t occ;
    RU(occ); 
    std::map < std::string, uint32_t > sumap;
    for (uint32_t i=0; i<occ; i++) {
        std::string key;
        uint32_t val;
        RS(key);
        RU(val);
        sumap[key] = val;
    }
    fclose(fp);
    return sumap;
}


std::map < Gram, uint32_t > unmarshall_gram_uint32_map(std::string filename) {
    FILE *fp = fopen ((char*)filename.c_str(), "r");
    uint32_t occ;
    RU(occ); 
    std::map < Gram, uint32_t > gumap;
    for (uint32_t i=0; i<occ; i++) {
        Gram g;
        RU(g);
        uint32_t val;    
        RU(val);
        gumap[g] = val;
    }
    fclose(fp);
    return gumap;
}


std::map < uint32_t, std::string > unmarshall_uint32_string_map(std::string filename) {
    FILE *fp = fopen ((char*)filename.c_str(), "r");
    uint32_t occ;
    RU(occ); 
    std::map < uint32_t, std::string > usmap;
    for (uint32_t i=0; i<occ; i++) {
        uint32_t key;
        std::string val;
        RU(key);
        RS(val);
        usmap[key] = val;
    }
    fclose(fp);
    return usmap;
}



void marshall_summary(const std::string filename_prefix, InvIndex &inv) {
    std::string filename = filename_prefix + ".summary";
    // 1 file. first write out summary info
    FILE *fp = fopen((char *) filename.c_str(), "w");
    WS(inv.filename_prefix);  
    WU(inv.min_n_gram);
    WU(inv.max_n_gram);
    WU(inv.passage_len_bytes);
    WU(inv.num_passages);
    fclose(fp);
}  
  

void unmarshall_summary(const std::string filename_prefix, InvIndex *inv) {
    std::string filename = filename_prefix + ".summary";
    // 1 file. first write out summary info
    FILE *fp = fopen((char *) filename.c_str(), "r");
    RS(inv->filename_prefix);
    RU(inv->min_n_gram);
    RU(inv->max_n_gram);
    RU(inv->passage_len_bytes);
    RU(inv->num_passages);
    fclose(fp);
}  



			      
// marshalls everything *except* the doc-word arrays
void marshall_invindex_min(InvIndex &inv) {
    std::string pfx = inv.filename_prefix;
    marshall_summary(pfx, inv);
    std::string filename;
    for (uint32_t n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        // n files.  lexicon
        filename = pfx + ".lexicon-" + std::to_string(n);
        marshall_lexicon(filename, inv.lexicon[n]);
        // n files.  map 
        filename = pfx + ".inv-map-" + std::to_string(n);
        marshall_gram_long_map(filename, inv.map_dw[n]);
        // n files. general gram counts for each gram foreach n
        filename = pfx + ".gen-" + std::to_string(n);
        marshall_gram_uint32_map(filename, inv.general_query[n]);
    }
    // 1 file.  total count foreach n
    filename = pfx + ".total_count";
    marshall_uint32_uint32_map(filename, inv.total_count);
    // 1 file.  map from filename to first passage number
    filename = pfx + ".f2fp";
    marshall_string_uint32_map(filename, inv.filename_to_first_passage);
    // 1 file.  map from first passage number to filename
    filename = pfx + ".fpf2";
    marshall_uint32_string_map(filename, inv.first_passage_to_filename);
}
 


// unmarshalls everything except the doc-word arrays
InvIndex *unmarshall_invindex_min(std::string pfx) {
    InvIndex *inv = new InvIndex;    
    // 1 file. first read summary info
    unmarshall_summary(pfx, inv);
    std::string filename;
    for (uint32_t n=inv->min_n_gram; n<=inv->max_n_gram; n++) {        
        filename = pfx + ".lexicon-" + (std::to_string(n));
        inv->lexicon[n] = unmarshall_lexicon(filename, n);
        // n files.  inv-maps
        filename = pfx + ".inv-map-" + std::to_string(n);
        inv->map_dw[n] = unmarshall_gram_long_map(filename);
        // n files. general gram counts for each gram foreach n
        filename = pfx + ".gen-" + std::to_string(n);
        inv->general_query[n] = unmarshall_gram_uint32_map(filename);
    }
    // 1 file.  total count foreach n
    filename = pfx + ".total_count";
    inv->total_count = unmarshall_uint32_uint32_map(filename);
    // Load the filename <-> first passage #  maps
    // 1 file.  map from filename to first passage number
    filename = pfx + ".f2fp";
    inv->filename_to_first_passage = unmarshall_string_uint32_map(filename);
    // 1 file.  map from first passage number to filename
    filename = pfx + ".fpf2";
    inv->first_passage_to_filename = unmarshall_uint32_string_map(filename); 
    return inv;
}

 

/*

  Marshall a row in the inverted index
  format is:

  occ  
  passage_ind[0] count[0] 
  passage_ind[1] count[1] 
  passage_ind[2] count[2] 
  ...
  passage_ind[occ-1] count[occ-1]

  where all of occ, passage_ind, and count are uint32_t 

  NB: we grab these passage_ind, count pairs out of a map, 
  but we put them into an array sorted by passage_ind
  before we write them out.

*/


bool compare_by_passage_ind(const CountPair &a, const CountPair &b) {
    return (a.passage_ind < b.passage_ind);
}


static GramPsgCounts row;
static bool row_init = true;

void resize_doc_word(GramPsgCounts &row, uint32_t desired_size) {
    if (row_init) {
        row_init = false;
        row.size = 0;
        row.counts = NULL;
        row.max_size = desired_size;
        row.counts = (CountPair *) malloc(sizeof(CountPair) * row.max_size);
    }
    // we only ever grow this thing
    if (row.max_size < desired_size) {
        row.max_size = desired_size;
        row.counts = (CountPair *) realloc(row.counts, sizeof(CountPair) * row.max_size);
    }
}


void marshall_row_fp(FILE *fp, GramPsgCounts &row) {
    WU(row.size);
    fwrite((void *) row.counts, sizeof(CountPair), row.size, fp);
}



// marshall this doc word row to fp 
// note, this is the doc word map from inv
void marshall_doc_word_fp(FILE *fp, std::map < uint32_t, uint32_t > &doc_word) {
    assert (doc_word.size() != 0);
    // this is length of this row
    uint32_t occ = doc_word.size();
    resize_doc_word(row, occ);
    row.size = occ;
    uint32_t i=0;
    for ( auto &kvp : doc_word ) {
        row.counts[i].passage_ind = kvp.first;
        row.counts[i].count = kvp.second;
        i++;
    }
    // NB: dont need to sort data since it came from a map.  
    // they should be in order by passage_ind, which is what we want
    marshall_row_fp(fp, row);
}




// unmarshall doc word row for this gram
int unmarshall_row_fp(FILE *fp, InvIndex *inv, uint32_t n, const Gram gram, GramPsgCounts &row ) {
    //  printf ("pos = %d\n", inv->map_dw[n][gram]);
    fseek(fp, inv->map_dw[n][gram], SEEK_SET);
    uint32_t occ;
    RU(occ);
    //  printf ("occ=%d\n", occ);
    // some on-the-fly pruning
    if (occ > max_row_length) {
        return 0;
    }
    resize_doc_word(row, occ);
    row.size = occ;
    fread(row.counts, sizeof(CountPair), occ, fp);
    return 1;
}  

 

std::map < uint32_t, uint32_t > unmarshall_doc_word_fp(FILE *fp, InvIndex *inv, uint32_t n, Gram gram) {
    GramPsgCounts row;
    row.max_size = 0;
    row.size = 0;
    row.counts = NULL;
    int ret = unmarshall_row_fp(fp, inv, n, gram, row);
    assert (ret == 1);
    std::map < uint32_t, uint32_t > dw;
    for (uint32_t i=0; i<row.size; i++) {
        dw[row.counts[i].passage_ind] = row.counts[i].count;
    }
    return dw;
}

/*

  .inv-n file format
  foreach n:
  uint32_t occ      // number of grams in lexicon n
  foreach gram in lexicon [n]:
  marshall_doc_word for that gram (see fn)

  (other index files written by marshall_invindex_min)

*/
void marshall_invindex(InvIndex &inv) {
    std::string pfx = inv.filename_prefix;
    for (uint32_t n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        // n files.  inv index map.
        std::string filename = pfx + ".inv-map-" + std::to_string(n);
        FILE *fpinvmap = fopen((char *) filename.c_str(), "w");
        uint32_t occ = inv.lexicon[n].grams.size();
        fwrite(&occ, sizeof(occ), 1, fpinvmap);
        // n files.  inv index.
        filename = pfx + ".inv-" + std::to_string(n);
        FILE *fpinv = fopen((char *) filename.c_str(), "w");
        // create map_dw here
        for ( auto &gram : inv.lexicon[n].grams ) {           
            inv.map_dw[n][gram] = ftell(fpinv);      
            marshall_doc_word_fp(fpinv, inv.docs_with_word[n][gram]);
        }
        fclose(fpinv);
        fclose(fpinvmap);
    }
    // NB: have to do this last b/c otherwise invindex->map_dw not populated
    marshall_invindex_min(inv);
}

void marshall_passage(Passage &passage, FILE *fp) {
    WU(passage.uind);
    uint32_t l = passage.contents.size();
    WU(l);
    for ( auto &kvp : passage.contents ) {
        uint32_t n = kvp.first;
        PassageDist pd = kvp.second;
        WU(n);
        WU(pd.total);
        uint32_t l2 = pd.count.size();
        WU(l2);
        for ( auto &kvp : pd.count ) {
            Gram gram = kvp.first;
            uint32_t count = kvp.second;
            WU(gram);
            WU(count);
        }
    }
}

Passage unmarshall_passage(FILE *fp) {
    Passage passage;
    RU(passage.uind);
    // l is the size of the contents map
    uint32_t l;
    RU(l);
    for(uint32_t i=0; i<l; i++) {
        PassageDist pd;        
        uint32_t n;
        RU(n);
        assert (n<=8);
        pd.n = n;
        RU(pd.total);
        uint32_t l2;
        RU(l2);
        for (uint32_t j=0; j<l2; j++) {
            Gram gram;
            uint32_t count;
            RU(gram);
            RU(count);
            pd.count[gram] = count;
        }
        passage.contents[n] = pd;
    }
    return passage;
}
        
    

void marshall_index(Index &index) {
    std::string filename = index.filename_prefix + ".ind.summary";
    FILE *fp = fopen((char *) filename.c_str(), "w");
    WU(indc->min_n_gram);
    WU(indc->max_n_gram);
    WU(index.passage_len_bytes);
    WU(index.num_passages);
    fclose(fp);
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        std::string filename = std::string(index.filename_prefix) + ".ind.lexicon-" + (std::to_string(n));
        printf ("marshalling lexicon n=%d occ=%d\n", (int) n, (int) indc->lexicon[n].grams.size());
        marshall_lexicon(filename, indc->lexicon[n]);
    }
    filename = index.filename_prefix + ".ind.b2u";
    fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = index.binary_to_uind.size();
    WU(occ);
    printf ("marshalling binary_to_uind occ=%d\n", occ);
    for ( auto &kvp : index.binary_to_uind ) {       
        WS(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
    filename = index.filename_prefix + ".ind.utp";
    fp = fopen((char *) filename.c_str(), "w");
    occ = index.uind_to_passage.size();
    WU(occ);
    printf ("marshalling uind_to_passage occ=%d\n", occ);
    for ( auto &kvp : index.uind_to_passage ) {
        WU(kvp.first);
        Passage &passage = kvp.second;
        marshall_passage(passage, fp);
    }
    fclose(fp);
    filename = index.filename_prefix + ".ind.passages";
    fp = fopen((char *) filename.c_str(), "w");
    occ = index.passages.size();
    WU(occ);
    printf ("marshalling passages to uind occ=%d\n", occ);
    for (uint32_t i=0; i<occ; i++) {
        uint32_t passage_ind = index.passages[i];
        WU(passage_ind);
    }
    fclose(fp);
    printf ("marshalling uind to psgs\n");
    filename = index.filename_prefix + ".ind.uind_to_psgs";
    fp = fopen((char *) filename.c_str(), "w");
    occ = index.uind_to_psgs.size();
    WU(occ);  
    for ( auto &kvp : index.uind_to_psgs ) {
        uint32_t uind = kvp.first;
        WU(uind);
        occ = kvp.second.size();
        WU (occ);
        for ( auto &el : kvp.second ) {
            WU(el);
        }
    }
    fclose(fp);
    printf ("marshalling f2fp and fp2f\n");
    if (index.filename_to_first_passage.size() == 0) {
        index.filename_to_first_passage[index.filename_prefix] = 0;
        index.first_passage_to_filename[0] = index.filename_prefix;
    }
    filename = index.filename_prefix + ".ind.f2fp";
    printf ("%d\n", (int) index.filename_to_first_passage.size());
    marshall_string_uint32_map(filename, index.filename_to_first_passage);
    filename = index.filename_prefix + ".ind.fp2f";
    printf ("%d\n", (int) index.first_passage_to_filename.size());
    marshall_uint32_string_map(filename, index.first_passage_to_filename);
    printf ("done marshalling index\n");
}


Index *unmarshall_index(std::string pfx) {
    Index *index = new Index;
    std::string filename = pfx + ".ind.summary";
    FILE *fp = fopen((char *) filename.c_str(), "r");
    RU(index->min_n_gram);
    RU(index->max_n_gram);
    RU(index->passage_len_bytes);
    RU(index->num_passages);
    fclose(fp);
    for (uint32_t n=index->min_n_gram; n<=index->max_n_gram; n++) {
        filename = pfx + ".ind.lexicon-" + (std::to_string(n));
        index->lexicon[n] = unmarshall_lexicon(filename, n);
    }
    filename = pfx + ".ind.passages";
    /*
    fp = fopen((char *) filename.c_str(), "r");
    printf ("%d passages\n", index->num_passages);
    for (uint32_t i=0; i<index->num_passages; i++) {
        Passage passage = unmarshall_passage(fp);
        index->passages[passage.ind] = &passage;
    }
    */
    filename = pfx + ".ind.f2fp";
    index->filename_to_first_passage = unmarshall_string_uint32_map(filename);
    filename = pfx + ".ind.fp2f";
    index->first_passage_to_filename = unmarshall_uint32_string_map(filename); 
    return index;
}
    


void marshall_invindex(InvIndex *inv) {
    marshall_invindex(*inv);
}


void marshall_index(Index *index) {
    marshall_index(*index);
}

// construct passage name from ind, using first_passage_to_filename
// passage_name assumed alloc big enough to fit filename-offset
std::string get_passage_name(InvIndex &inv, uint32_t passage_ind, uint32_t *start_pos) {
    auto x = (inv.first_passage_to_filename.upper_bound(passage_ind));
    x--;
    std::string filename = x->second;
    uint64_t offset;
    if ((passage_ind % 2) == 0) {
        uint32_t num_chunks = passage_ind / 2;
        offset = num_chunks * inv.passage_len_bytes;
    }
    else {
        uint32_t num_chunks = (passage_ind - 1) / 2;
        offset = inv.passage_len_bytes/2 + num_chunks * inv.passage_len_bytes;
    }
    *start_pos = offset;
    return filename;
}


void marshall_preprocessed_scores(PpScores *pps) {
    std::string filename = pps->filename_prefix + ".pp";
    FILE *fp = fopen((char *) filename.c_str(), "w");
    WU(pps->max_n_gram);
    WU(pps->num_passages);
    uint32_t num_mgrams = pps->scorerow.size();
    WU(num_mgrams);
    printf ("marshalling preprocessed scores for %d max_ngrams\n", num_mgrams);
    int tot10 = num_mgrams/10;  
    uint32_t i = 0;
    for ( auto &kvp : pps->scorerow ) {
        if ((i % tot10) == 0) { printf ("i=%d\n",i); }  
        Gram gram = kvp.first;
        WU(gram);
        ScoreRow sr = kvp.second;
        WU(sr.len);
        fwrite ((void *) sr.el, sizeof(sr.el[0]), sr.len, fp);
        i ++ ;
    }
    fclose (fp);
}




// unmarshalls the per-max-n-gram precomputed scores so that bir.cpp can be wicked fast
// NB: this has to return a ptr to a PpScores for the C API to work
PpScores *unmarshall_preprocessed_scores(std::string filename_pfx) {
    PpScores *pps = new PpScores;
    std::string filename = filename_pfx + ".pp";
    FILE *fp = fopen((char *) filename.c_str(), "r");
    RU(pps->max_n_gram);
    RU(pps->num_passages);
    uint32_t num_mgrams;
    RU(num_mgrams);
    printf ("unmarshalling preprocessed scores for %d max_ngrams\n", num_mgrams);
    int tot10 = num_mgrams/10;
    for (uint32_t i=0; i<num_mgrams; i++) {
        if ((i % tot10) == 0) { printf ("i=%d\n",i); }
        Gram gram;
        RU(gram);
        uint32_t rowsize;
        RU(rowsize);
        printf ("rowsize = %d\n", rowsize);
        assert (rowsize <= pps->num_passages);
        pps->scorerow[gram].len = rowsize;
        pps->scorerow[gram].el = (Score *) malloc (sizeof (Score) * rowsize);
        uint32_t nn = fread((void *) pps->scorerow[gram].el, sizeof (Score), rowsize, fp);
        assert(nn==rowsize);
    }
    printf ("done\n");
    return pps;
}                





/*
  Count n-grams for this binary blob (a passage).
  The lexicon and index both get updated.
*/
void index_this_passage(IndexCommon *indc, Index *index, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) {    
    // maintain map a from binary passages to ints
    std::string sb = std::string((const char *) binary_passage, len);
    uint32_t uind;
    if (index->binary_to_uind.find(sb) == index->binary_to_uind.end()) {
        // new pasage
        uind = index->binary_to_uind.size();
        if ((uind % 1000) == 0) {
            printf ("%d unique passages indexed.  %d passages observed\n", (int) uind, (int) index->passages.size());
        }
        index->binary_to_uind[sb] = uind;
        index->uind_to_passage[uind] = 
            index_passage(indc, /*updatelexicon = */ true, binary_passage, len, uind);        
    }
    else {
        uind = index->binary_to_uind[sb];
    }       
    index->num_passages ++;
    index->passages[passage_ind] = uind;
    if (index->uind_to_psgs.find(uind) == index->uind_to_psgs.end()) {
        // keeps track of set of passages for this uind
        index->uind_to_psgs[uind].insert(passage_ind);
    }
    assert (index->num_passages == index->passages.size());
}


// c version
void index_this_passage_c(void *vpindc, void *vpindex, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    Index *index = reinterpret_cast<Index *> (vpindex);
    index_this_passage(indc, index, binary_passage, len, passage_ind);
}




InvIndex *invert(Index *index) {
    int i;
    printf ("Inverting index\n");
    InvIndex *inv = new InvIndex;
    uint32_t min_n = index->min_n_gram;
    uint32_t max_n = index->max_n_gram;
    inv->min_n_gram = min_n;
    inv->max_n_gram = max_n;
    inv->passage_len_bytes = index->passage_len_bytes;
    inv->lexicon = index->lexicon;
    inv->filename_to_first_passage = index->filename_to_first_passage;
    inv->first_passage_to_filename = index->first_passage_to_filename;
    inv->uind_to_psgs = index->uind_to_psgs;
    // iterate over passages in the index
    uint32_t ii=0;
    uint32_t tot = index->uind_to_passage.size();
    uint32_t i100 = tot / 100;
    for ( auto &kvp : index->uind_to_passage ) {
        if (ii > 0 && (ii % i100) == 0) {
            printf ("%d %d \n", ii, tot);
        }
        ii ++;
        uint32_t uind = kvp.first;
        Passage &passage = kvp.second;
        // iterate over distributions in this passage
        for ( auto &kvp : passage.contents ) {
            uint32_t n = kvp.first;
            PassageDist pd = kvp.second;
            // iterate over gram counts in this distribution
            for ( auto &kvp : pd.count ) {
                Gram gram = kvp.first;
                uint32_t count = kvp.second;
                inv->docs_with_word[pd.n][gram][passage.uind]++;
                inv->general_query[pd.n][gram] ++;
                inv->total_count[pd.n] += count;
            }
        }
    }
    // create map from index back to passage name (a string)
    // and populate passage lengths in inv index
    inv->num_passages = index->num_passages;
    // NB: inv->filename_prefix unspecified at this time
    // NB: inv->map_dw doesnt exist yet. 
    // this is generated when we write out the file
    return inv;
}     



static bool compare_scores (const Score & s1, const Score & s2) {
    return (s1.val > s2.val);
}


// query is a passage.  



std::vector < Score > score;
/*
  query contains a passage
  scorepair is preprocessed score arrays. let n = scorepare[max_n_gram].first.  
  scorepair[max_n_gram].second is a c array of n Score structs 
  scorepair[max_n_gram].second[i].ind is a passage ind and .val is the preprocessed score to add for that psg.
*/ 
void query_with_passage (Passage &query, PpScores &pps, uint32_t *ind, float *best_score) {
    if (score.size() < pps.num_passages) {
        score.resize(pps.num_passages);
        printf ("score is now %d len\n", (int) score.size());
    }
    // clear the scores
    for (uint32_t i = 0; i < pps.num_passages; i++) {
        score[i].ind = i;
        score[i].val = 0.0;
    }
    // iterate over highest order ngrams in the "query"
    for (auto &kvp : query.contents[pps.max_n_gram].count)    {
        Gram gram = kvp.first;
        //        printf ("gram = ");
        //        spit_gram_hex(gram, pps.max_n_gram);
        uint32_t gram_count = kvp.second;
        uint32_t rowsize = pps.scorerow[gram].len;
        //        printf ("gram_count = %d  rowsize = %d\n", gram_count, rowsize);
        Score *sp = pps.scorerow[gram].el;
        for (uint32_t i=0; i<rowsize; i++) {
            uint32_t psgid = sp[i].ind; 
            //            printf ("score %d += %d * %.2f\n", psgid, gram_count, sp[i].val);
            score[psgid].val += gram_count * sp[i].val;
        }
    }
    // scale the scores
    float max_score = -10000.0;
    uint32_t argmax = 0;
    float min_score = 10000.0;
    //    uint32_t argmin = 0;
    for (uint32_t i = 0; i < pps.num_passages; i++) {
        score[i].val /= query.contents[pps.max_n_gram].total;
        if (score[i].val > max_score) {
            max_score = score[i].val;
            argmax = i;
        }
        /*
        if (score[i].val < min_score) {
            min_score = score[i].val;
            argmin = i;
        }
        */
    }
    std::sort (score.begin (), score.end (), compare_scores);  
    for (uint32_t i=0; i<5; i++) {
        printf ("%d %d %.4f\n", i, score[i].ind, score[i].val);
    }

    printf ("min_score = %.5f\n", min_score);
    *ind = argmax;
    *best_score = max_score;
}





void *invert_c(void *vpindex) {
    Index *index = reinterpret_cast<Index *> (vpindex);
    InvIndex *inv = invert(index);
    return reinterpret_cast<void *> (inv);
}


// c version
void marshall_invindex_c(void *vpinv, char *file_pfx) {
    InvIndex *inv = reinterpret_cast<InvIndex *> (vpinv);
    inv->filename_prefix = std::string(file_pfx);
    marshall_invindex(inv);
}

void marshall_index_c(void *vpindex, char *file_pfx) {
    Index *index = reinterpret_cast<Index *> (vpindex);
    index->filename_prefix = std::string(file_pfx);
    marshall_index(index);
}


void *unmarshall_preprocessed_scores_c (char *filename_pfx) {
    PpScores *pps = unmarshall_preprocessed_scores(std::string(filename_pfx));
    return reinterpret_cast <void *> (pps);
}


void query_with_passage_c (void *vppassage, void *vppps, uint32_t *ind, float *score) {
    Passage *passage = reinterpret_cast<Passage *>(vppassage);
    PpScores *pps = reinterpret_cast<PpScores *>(vppps);
    query_with_passage(*passage, *pps, ind, score);
}


void new_index_common_c(char *filename_prefix, 
                        uint32_t min_n_gram, uint32_t max_n_gram,
                        uint32_t passage_len_bytes) {
    IndexCommon *indc = new_index_common(std::string(filename_prefix),
                                         min_n_gram, max_n_gram, passage_len_bytes);
    return reinterpret_cast<void *> (indc);
}

// c version
void *new_index_c() {
    Index *index = new Index;
    return reinterpret_cast<void *> (ind);
}

void indexer_set_passage_len_bytes_c(void *vpindc, uint32_t passage_len_bytes) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    indc->passage_len_bytes = passage_len_bytes;
}

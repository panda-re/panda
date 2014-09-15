
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

#include <chrono>
#include <iostream>
#include <unordered_set>

uint32_t max_row_length=10000;


////////////////////////////////////////
// Index
Index new_index(uint32_t min_n_gram, uint32_t max_n_gram,
                uint32_t passage_len_bytes) {
    Index index = Index();  
    index.min_n_gram = min_n_gram;
    index.max_n_gram = max_n_gram;
    index.passage_len_bytes = passage_len_bytes;
    index.num_passages = 0;
    return index;
}



InvIndex invindex_min_new(char *pfx, uint32_t min_n, uint32_t max_n, uint32_t passage_len_bytes) {
    InvIndex inv;
    inv.filename_prefix = std::string(pfx);
    inv.min_n_gram = min_n;
    inv.max_n_gram = max_n;
    inv.passage_len_bytes = passage_len_bytes;
    return inv;
}





void spit_gram_hex(const Gram &gram, uint32_t n) {
    int i;
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
inline Gram gram64(char *buf, int n) {
    assert (n<=8);
    Gram g = ( *((uint64_t *) (buf))) & (0xffffffffffffffff >> (64 - n*8));
    return g;
}
  

// returns sub-gram starting at pos of len bytes
Gram gramsub(Gram &g, uint32_t pos, uint32_t len) {
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
    printf ("ind=%d \n", passage.ind);
    // iterate over n
    for ( auto &kvp : passage.contents ) {
        printf ("n=%d\n", kvp.first);
        spit_passage_dist(kvp.second);
    }
    printf ("Passage ]\n");
}


 
void spit_lexicon(Lexicon &lexicon) {
    printf ("Lexicon [\n");
    printf ("size=%d\n", lexicon.grams.size());
    for ( auto &gram : lexicon.grams ) {    
        printf ("gram : ") ;
        spit_gram_hex(gram, lexicon.n);
        printf ("\n");
    }
    printf ("Lexicon ]\n");
}

void spit_index(Index &index) {
    printf ("Index [\n");
    printf ("min,max ngrams = (%d,%d)\n", index.min_n_gram, index.max_n_gram);
    printf ("passage_len_bytes = %d\n", index.passage_len_bytes);
    printf ("Lexicons [\n");
    int n;
    for (n=index.min_n_gram; n<=index.max_n_gram; n++) {
        printf ("\nn=%d\n", n);
        spit_lexicon(index.lexicon[n]);
    }
    printf ("Lexicons ]\n");
    uint32_t num_passages = index.passages.size();
    printf ("%d passages\n", num_passages);
    printf ("Passages [\n");
    // iterate over passages
    for ( auto &kvp:index.passages ) {
        printf ("n=%d\n", kvp.first);
        spit_passage(kvp.second);
    }
    printf ("Passages ]\n");
    printf ("Index ]\n");
}



// collect n-gram distributions for passage.  length len.  may contain nulls
Passage index_passage (std::map < uint32_t, Lexicon > &lexicon, 
                       bool update,
                       uint32_t min_n, uint32_t max_n,
                       char *binary_passage, uint32_t len,
                       uint32_t passage_ind) {
    int n;
    Passage passage = Passage ();
    passage.ind = passage_ind;
    //passage.contents = std::map < uint32_t, PassageDist > (max_n+1);
    for (n=min_n; n<=max_n; n++) {
        PassageDist pd = PassageDist();
        pd.n = n;
        pd.total = 0;
        int i;
        for (i=0; i<=len-n; i++) {
            //  add / update count for n-gram starting at pos "start"
            Gram gram = gram64 (binary_passage+i, n);
            bool indexp = false;
            if (lexicon[n].grams.find(gram) == lexicon[n].grams.end()) {
                // gram is not in the lexicon
                if (update) {
                    // we are updating lexicon so add it
                    lexicon[n].grams.insert(gram);
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


// spits all all but doc_word arrays
void spit_inv_min(InvIndex &inv) {
    printf ("InvIndex [\n");
    printf ("filename_prefix = [%s]\n", inv.filename_prefix.c_str());
    printf ("min, max ngram = %d,%d\n", inv.min_n_gram, inv.max_n_gram);
    printf ("passage_len_bytes = %d\n", inv.passage_len_bytes);
    printf ("num_passages = %d\n", inv.num_passages);
    printf ("first_passage_to_filename [\n");
    for ( auto &kvp : inv.first_passage_to_filename ) {
        printf ("%d %s\n", kvp.first, kvp.second.c_str());
    }
    printf ("first_passage_to_filename ]\n");
    printf ("filename_to_first_passage [\n");
    for ( auto &kvp : inv.filename_to_first_passage ) {
        printf ("%s %d\n", kvp.first.c_str(), kvp.second);
    }
    printf ("first_passage_to_filename ]\n");

    printf ("Lexicons [\n");
    for (int n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        printf ("n=%d\n", n);
        spit_lexicon(inv.lexicon[n]);
    }
    printf ("Lexicons ]\n");
    printf ("general_query [\n");
    for (int n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        printf ("n=%d\n", n);
        for ( auto &kvp : inv.general_query[n] ) {
            printf ("  ");
            spit_gram_hex(kvp.first, n);
            printf (" %d\n", kvp.second);
        }
    }
    printf ("general_query ]\n");
    printf ("InvIndex ]\n");
}


void spit_inv(InvIndex &inv) {
    spit_inv_min(inv);
    printf ("docs_with_word [\n");
    for (int n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
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


void marshall_lexicon(char *filename, Lexicon &lexicon){ 
    FILE *fp = fopen (filename, "w");
    uint32_t occ = lexicon.grams.size();
    WU(occ);
    WU(lexicon.n);
    for ( auto &gram : lexicon.grams ) {
        WU(gram);
    }
    fclose(fp);
}


void marshall_uint32_uint32_map(char *filename, std::map < uint32_t, uint32_t > &uumap) {
    FILE *fp = fopen (filename, "w");
    uint32_t occ = uumap.size();
    WU(occ);
    for ( auto &kvp : uumap ) {
        WU(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}


void marshall_gram_long_map(char *filename, std::map < Gram, long > &glmap ) {
    FILE *fp = fopen(filename, "w");
    uint32_t occ = glmap.size();
    WU(occ);
    bool first = true;
    for ( auto &kvp : glmap ) {
        Gram g = kvp.first;
        WU(g);
        WL(kvp.second);
    }
    fclose(fp);
}



void marshall_gram_uint32_map(char *filename, std::map < Gram, uint32_t > &gumap ) {
    FILE *fp = fopen(filename, "w");
    uint32_t occ = gumap.size();
    WU(occ);
    for ( auto &kvp : gumap ) {
        Gram g = kvp.first;
        WU(g);
        WU(kvp.second);
    }
    fclose(fp);
}


void marshall_string_uint32_map(char *filename, std::map < std::string, uint32_t > &sumap ) {
    FILE *fp = fopen(filename, "w");
    uint32_t occ = sumap.size();
    WU(occ);
    for ( auto &kvp : sumap ) {
        WS(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
}



void marshall_uint32_string_map(char *filename, std::map < uint32_t, std::string > &usmap ) {
    FILE *fp = fopen(filename, "w");
    uint32_t occ = usmap.size();
    WU(occ);
    for ( auto &kvp : usmap ) {
        WU(kvp.first);
        WS(kvp.second);
    }
    fclose(fp);
}



Lexicon unmarshall_lexicon(char *filename) {
    FILE *fp = fopen (filename, "r");
    uint32_t occ;
    RU(occ);
    Lexicon lexicon;
    RU(lexicon.n);
    for (uint32_t i=0; i<occ; i++) {
        Gram gram;
        RU(gram);    
        lexicon.grams.insert(gram);
    }
    fclose(fp);
    return (lexicon);
}


std::map < uint32_t, uint32_t > unmarshall_uint32_uint32_map(char *filename) {
    FILE *fp = fopen (filename, "r");
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


std::map < Gram, long > unmarshall_gram_long_map(char *filename) {
    FILE *fp = fopen (filename, "r");
    uint32_t occ;
    RU(occ); 
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
			      

std::map < std::string, uint32_t > unmarshall_string_uint32_map(char *filename) {
    FILE *fp = fopen (filename, "r");
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


std::map < Gram, uint32_t > unmarshall_gram_uint32_map(char *filename) {
    FILE *fp = fopen (filename, "r");
    uint32_t occ;
    RU(occ); 
    std::map < Gram, uint32_t > gumap;
    Gram g;
    for (uint32_t i=0; i<occ; i++) {
        RU(g);
        uint32_t val;    
        RU(val);
        gumap[g] = val;
    }
    fclose(fp);
    return gumap;
}


std::map < uint32_t, std::string > unmarshall_uint32_string_map(char *filename) {
    FILE *fp = fopen (filename, "r");
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



void marshall_summary(const char *filename_prefix, InvIndex &inv) {
    char filename[65535];
    // 1 file. first write out summary info
    sprintf(filename, "%s.summary", filename_prefix);
    FILE *fp = fopen(filename, "w");
    WS(inv.filename_prefix);  
    WU(inv.min_n_gram);
    WU(inv.max_n_gram);
    WU(inv.passage_len_bytes);
    WU(inv.num_passages);
    fclose(fp);
}  
  

void unmarshall_summary(const char *filename_prefix, InvIndex &inv) {
    char filename[65535];
    // 1 file. first write out summary info
    sprintf(filename, "%s.summary", filename_prefix);
    FILE *fp = fopen(filename, "r");
    RS(inv.filename_prefix);
    RU(inv.min_n_gram);
    RU(inv.max_n_gram);
    RU(inv.passage_len_bytes);
    RU(inv.num_passages);
    fclose(fp);
}  



			      
// marshalls everything *except* the doc-word arrays
void marshall_invindex_min(InvIndex &inv) {
    const char *pfx = inv.filename_prefix.c_str();
    char filename[65535];
    marshall_summary(pfx, inv);
    int n,p;
    for (n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        // n files. write out passage len for each n and each psg
        //    sprintf(filename, "%s.passage_len-%d", pfx, n);  
        //    marshall_uint32_uint32_map(filename, inv.passage_len[n]);
        // n files.  lexicon
        sprintf(filename, "%s.lexicon-%d", pfx, n);
        marshall_lexicon(filename, inv.lexicon[n]);
        // n files.  map 
        sprintf(filename, "%s.inv-map-%d", pfx, n);
        marshall_gram_long_map(filename, inv.map_dw[n]);
        // n files. general gram counts for each gram foreach n
        sprintf(filename, "%s.gen-%d", pfx, n);
        marshall_gram_uint32_map(filename, inv.general_query[n]);
    }
    // 1 file.  total count foreach n
    sprintf(filename, "%s.total_count", pfx);
    marshall_uint32_uint32_map(filename, inv.total_count);
    // 1 file.  map from filename to first passage number
    sprintf(filename, "%s.f2fp", pfx);
    marshall_string_uint32_map(filename, inv.filename_to_first_passage);
    // 1 file.  map from first passage number to filename
    sprintf(filename, "%s.fp2f", pfx);
    marshall_uint32_string_map(filename, inv.first_passage_to_filename);
}
 


// unmarshalls everything except the doc-word arrays
InvIndex unmarshall_invindex_min(char *filename_pfx) {
    int i,n,p;
    InvIndex inv = InvIndex();
    char filename[65535];
    // 1 file. first read summary info
    unmarshall_summary(filename_pfx, inv);
    for (n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        // n files. passage lengths
        //        sprintf(filename, "%s.passage_len-%d", filename_pfx, n);  

        //        auto t1 = std::chrono::high_resolution_clock::now();

        //        inv.passage_len[n] = unmarshall_uint32_uint32_map(filename);
        //        auto t2 = std::chrono::high_resolution_clock::now();
        //        float elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        //        printf ("unm psg len n=%d occ=%d %.2f seconds\n", n, inv.passage_len[n].size(), elapsedSeconds);
        int x;
        //    std::cout << "Please enter a number: ";
        //    std::cin >> x;

        // n files.  lexicons

        auto t1 = std::chrono::high_resolution_clock::now();
        sprintf(filename, "%s.lexicon-%d", filename_pfx, n);

        inv.lexicon[n] = unmarshall_lexicon(filename);

        auto t2 = std::chrono::high_resolution_clock::now();
        float elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        printf ("unm lex n=%d occ=%d %.2f seconds\n", n, inv.lexicon[n].grams.size(), elapsedSeconds);
        //    std::cout << "Please enter a number: ";
        //    std::cin >> x;


        // n files.  inv-maps
        sprintf(filename, "%s.inv-map-%d", filename_pfx, n);

        t1 = std::chrono::high_resolution_clock::now();

        inv.map_dw[n] = unmarshall_gram_long_map(filename);

        t2 = std::chrono::high_resolution_clock::now();
        elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        printf ("unm map n=%d occ=%d %.2f seconds\n", n, inv.map_dw[n].size(), elapsedSeconds);
        //    std::cout << "Please enter a number: ";
        //    std::cin >> x;


        // n files. general gram counts for each gram foreach n
        sprintf(filename, "%s.gen-%d", filename_pfx, n);


        t1 = std::chrono::high_resolution_clock::now();

        inv.general_query[n] = unmarshall_gram_uint32_map(filename);

        t2 = std::chrono::high_resolution_clock::now();
        elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        printf ("unm ge n=%d occ=%d %.2f seconds\n", n, inv.general_query[n].size(), elapsedSeconds);
        //    std::cout << "Please enter a number: ";
        //    std::cin >> x;


    }
    // 1 file.  total count foreach n
    sprintf(filename, "%s.total_count", filename_pfx);
    inv.total_count = unmarshall_uint32_uint32_map(filename);

    // Load the filename <-> first passage #  maps
    // 1 file.  map from filename to first passage number
    sprintf(filename, "%s.f2fp", filename_pfx);
    inv.filename_to_first_passage = unmarshall_string_uint32_map(filename);
    // 1 file.  map from first passage number to filename
    sprintf(filename, "%s.fp2f", filename_pfx);
    inv.first_passage_to_filename = unmarshall_uint32_string_map(filename); 
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
    if (row.max_size == 0) {
        // first time -- alloc
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
    //  printf ("marshalling row of %d items\n", row.size);
    WU(row.size);
    fwrite(row.counts, sizeof(CountPair), row.size, fp);
}



// marshall this doc word row to fp 
// note, this is the doc word map from inv
void marshall_doc_word_fp(FILE *fp, std::map < uint32_t, uint32_t > &doc_word) {
    if (row_init) {
        row_init = false;
        row.size = 0;
        row.max_size = 0;
        row.counts = NULL;
    }
    assert (doc_word.size() != 0);
    // this is length of this row
    uint32_t occ = doc_word.size();
    //  printf ("after writing occ, pos=%d\n", ftell(fp));
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
    //  printf ("after writing row, pos=%d\n", ftell(fp));

}




// unmarshall doc word row for this gram
int unmarshall_row_fp(FILE *fp, InvIndex &inv, uint32_t n, const Gram &gram, GramPsgCounts &row ) {
    //  printf ("pos = %d\n", inv.map_dw[n][gram]);
    fseek(fp, inv.map_dw[n][gram], SEEK_SET);
    uint32_t occ;
    RU(occ);
    //  printf ("occ=%d\n", occ);
    if (occ > max_row_length) {
        return 0;
    }
    resize_doc_word(row, occ);
    row.size = occ;
    fread(row.counts, sizeof(CountPair), occ, fp);
    return 1;
}  
 

std::map < uint32_t, uint32_t > unmarshall_doc_word_fp(FILE *fp, InvIndex &inv, uint32_t n, Gram &gram) {
    GramPsgCounts row;
    row.max_size = 0;
    row.size = 0;
    row.counts = NULL;
    unmarshall_row_fp(fp, inv, n, gram, row);
    std::map < uint32_t, uint32_t > dw;
    for (int i=0; i<row.size; i++) {
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
    std::string &pfx = inv.filename_prefix;
    int n;
    for (n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        printf ("n=%d\n", n);
        // n files.  inv index map.
        char filename[65535];
        sprintf(filename, "%s.inv-map-%d", pfx.c_str(), n);
        FILE *fpinvmap = fopen(filename, "w");
        uint32_t occ = inv.lexicon[n].grams.size();
        fwrite(&occ, sizeof(occ), 1, fpinvmap);
        // n files.  inv index.
        sprintf(filename, "%s.inv-%d", pfx.c_str(), n);
        FILE *fpinv = fopen(filename, "w");
        // create map_dw here
        for ( auto &gram : inv.lexicon[n].grams ) {
            /*
              printf ("GRAM = ");
              spit_gram_hex(gram, n);
              printf ("\n");
            */
            long pos = ftell(fpinv);      
            inv.map_dw[n][gram] = pos;
            marshall_doc_word_fp(fpinv, inv.docs_with_word[n][gram]);
        }
        fclose(fpinv);
        fclose(fpinvmap);
    }
    printf ("created map_dw\n");
    // NB: have to do this last b/c otherwise invindex->map_dw not populated
    marshall_invindex_min(inv);
}



// construct passage name from ind, using first_passage_to_filename
// passage_name assumed alloc big enough to fit filename-offset
const char *get_passage_name(InvIndex &inv, uint32_t passage_ind, uint32_t *start_pos) {
    auto x = (inv.first_passage_to_filename.upper_bound(passage_ind));
    x--;
    uint32_t first_passage = x->first;
    std::string filename = x->second;
    uint64_t pos = 0;
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
    return filename.c_str();
    //    sprintf (passage_name, "%s-%d", filename.c_str(), offset);
}

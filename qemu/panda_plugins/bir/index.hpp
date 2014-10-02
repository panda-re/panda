#ifndef __BIR_INDEX_H__
#define __BIR_INDEX_H__

extern "C"{  
#include <stdint.h>
}

#include <set>
#include <map>
#include <algorithm>
#include <vector>
#include <string>




/*

struct gram_struct {
    // val is actual gram.
    // lowest order byte is first byte in gram.  
    // excess high-order bytes are guaranteed to be zero
    uint64_t val;  

    // n as in n-gram.  
    // n=1 means just 1st byte will be non-zero. 
    // n=2 means first two will be non-zero
    uint32_t n;
  
    bool operator <(const gram_struct &g) const { 
        {
            if (this->n == g.n) {
                return this->val < g.val;
            }
            return this->n < g.n;
        }
    }
};

typedef gram_struct Gram;

*/

typedef uint64_t Gram;




typedef struct count_struct {
    uint32_t passage_ind;
    uint32_t count;
} CountPair;


typedef struct gram_psg_counts_struct {
    uint32_t size;
    uint32_t max_size;
    CountPair *counts;
} GramPsgCounts;


// an n-gram distribution for some value of n. 
// NB: a gram is stored in a 64-bit uint.  thus, max n=8
typedef struct ngram_dist_struct {
    uint32_t n;  // the value of n
    std::map < Gram, uint32_t > count;  // counts for grams
    uint32_t total;                       // total counts in this ngram 
} PassageDist;


// a passage is represented as an array of ngram distributions (one for each value of n)
typedef struct passage_struct {
    uint32_t uind;    // unique index for this passage
    // passage[n] = passage dist for this value of n
    std::map < uint32_t, PassageDist > contents;
} Passage;
   
typedef std::map < std::string, uint32_t > SIHashtable;

// maps binary blobs (can contain nulls) to indicies
typedef struct lexicon_struct {
    uint32_t n;
    std::set < Gram > grams;
} Lexicon;


// both index and inv index use this info
typedef struct index_common_struct {
    std::string filename_prefix;
    // min,max n-ngram to index
    uint32_t min_n_gram;        
    uint32_t max_n_gram;
    // indexing passages of this length
    uint32_t passage_len_bytes;
    // total passages in the index
    uint32_t num_passages; 
    // total uniq passages in the index
    uint32_t num_uind;
    // map from ngram "words" to uniq inds
    std::map < uint32_t, Lexicon > lexicon;
    // uind_to_psgs[uind] is the set  of passage inds that are all the same
    std::map < uint32_t, std::set < uint32_t > > uind_to_psgs;  
    // map from file names to first passage number for each
    std::map < std::string, uint32_t > filename_to_first_passage;
    // map from first passage number back to filename
    std::map < uint32_t, std::string > first_passage_to_filename;   
} IndexCommon;



typedef struct index_struct {
    // binary_to_uind[sb] = uind
    // where sb is the binary blob that is code
    // and uind is a unique int for each such binary
    std::map < std::string, uint32_t > binary_to_uind;
    // uind_to_passage[uind] is a passage
    std::map < uint32_t, Passage > uind_to_passage;
    // index.passages[passage_ind] is a uind
    std::map < uint32_t, uint32_t > passages;
} Index;





// inverted index.  
typedef struct invindex_struct {
    // this is the actual inverted index
    // docs_with_word[n] is a map with key being a gram (for this value of n), i.e., a string
    // docs_with_word[n][gram] is another map with key being a passage index, i.e., a uint32_t
    // docs_with_word[n][gram][passage_ind] is a count i.e a uint32_t
    std::map < uint32_t, std::map < Gram, std::map < uint32_t, uint32_t > > > docs_with_word;
    // pos in file for each of these items in the inv index
    // indexed by n and then ngram index.
    std::map < uint32_t, std::map < Gram, long > > map_dw;
    // total counts for each n gram n.
    std::map < uint32_t, uint32_t > total_count;
    // counts accumulated across documents
    // one for each ngram
    // inv.general_query[n][gram] is a count
    std::map < uint32_t, std::map < Gram, uint32_t > > general_query;
} InvIndex;


typedef struct score_struct {
    uint32_t ind;
    float val;
} Score;


typedef struct scorerow_struct {
    uint32_t len; // length of row
    Score *el;   // this is ptr to c array of len Score structs
} ScoreRow;

typedef struct pp_score_struct {
    std::vector < Score > score;
    // scorerow[maxn_gram] is row of preprocessed scores (for maxn_gram)
    std::map < Gram, ScoreRow > scorerow;
} PpScores;





#define RU(u)                                                  \
    {                                                          \
        size_t nnn = fread(&(u), sizeof(u), 1, fp);              \
        assert (nnn == 1);                                       \
    } 


#define WU(u)                                   \
    {                                           \
        fwrite (&(u), sizeof(u), 1, fp);		\
    } 

#define RL(l) RU(l)
#define WL(l) WU(l)

#define RS(s)                                                   \
    {                                                           \
        uint32_t l;                                             \
        fread(&l, sizeof(l), 1, fp);                            \
        char *cs = (char *) malloc(l+1);                        \
        fread(cs, 1, l, fp);                                    \
        cs[l] = '\0';                                           \
        s = std::string(cs,l);                                  \
    }

#define WS(s)                                   \
    {                                           \
        uint32_t l = s.size();                  \
        fwrite(&l, sizeof(l), 1, fp);           \
        const char *cs = s.c_str();             \
        fwrite(cs, 1, l, fp);                   \
    }


#define WR(x) {fwrite(&(x), sizeof(x), 1, fp);}


#define WRS(s) {                                \
        int l = strlen(s);                      \
        fwrite(&l, sizeof(l), 1, fp);           \
        fwrite(s, 1, l, fp);                    \
    }  

    

void marshall_index(std::string &filename, Index &index);    
Index *unmarshall_index(std::string pfx) ;


void *mi_malloc(size_t n) ;
void *mi_calloc(size_t nmemb, size_t memsz);
void *mi_realloc(void *p, size_t n);
void mi_free(void *p);

void marshall_binary_int_hashtable_fp(FILE *fp, SIHashtable &sih);
void marshall_string_int_hashtable_fp(FILE *fp, SIHashtable &sih);

Index *new_index(uint32_t min_n_gram, uint32_t max_n_gram,
                 uint32_t passage_len_bytes) ;
void spit_passage_dist(PassageDist &pd) ;
void spit_passage(Passage &passage);

void spit_index(Index &index);
void spit_inv(InvIndex &inv);

void marshall_invindex(InvIndex &inv);

void spit_inv_min(InvIndex *inv) ;

void marshall_invindex_min(InvIndex &inv);


void spit_invindex(InvIndex &invindex);
void temp_count(SIHashtable &tcount, std::string n_gram, uint32_t n);


void resize_doc_word(GramPsgCounts &row, uint32_t desired_size);


// called by inv_spit and also retriever
// which use an array for rows
// returns 0 on fail (row too long)
// else returns 1
int unmarshall_row_fp(FILE *fp, InvIndex *inv, uint32_t n, const Gram gram, GramPsgCounts &row );

// called by merger which keeps rows in an array
void marshall_row_fp(FILE *fp, GramPsgCounts &row) ;

std::map < uint32_t, uint32_t > unmarshall_doc_word_fp(FILE *fp, InvIndex *inv, uint32_t n, Gram gram);


void marshall_doc_word_fp(FILE *fp, std::map < uint32_t, uint32_t > &doc_word);

InvIndex  *invindex_min_new(std::string pfx, uint32_t min_n, uint32_t max_n, uint32_t passage_len_bytes) ;

void spit_gram_hex(const Gram gram, uint32_t n);


Gram gramsub(Gram g, uint32_t pos, uint32_t len);


std::string get_passage_name(IndexCommon *indc, uint32_t passage_ind, uint32_t *start_pos);




InvIndex *invert(IndexCommon *indc, Index *index);

void marshall_invindex(IndexCommon *indc, InvIndex *inv);
void index_this_passage(IndexCommon *indc, Index *ind, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) ;


IndexCommon *new_index_common(std::string pfx, uint32_t min_n_gram, uint32_t max_n_gram, uint32_t passage_len_bytes);

void marshall_preprocessed_scores(IndexCommon *indc, PpScores *pps);
void marshall_index_common(IndexCommon *indc);



Index *unmarshall_index(std::string pfx, IndexCommon *indc) ;

// bir.cpp uses these
PpScores *unmarshall_preprocessed_scores(std::string filename_pfx);
IndexCommon *unmarshall_index_common(const std::string pfx);

Index *unmarshall_index(std::string pfx, IndexCommon *indc, bool passages) ;

// if uind_to_psgs is false, then we DONT load
IndexCommon *unmarshall_index_common(const std::string pfx, bool uind_to_psgs) ;
InvIndex *unmarshall_invindex_min(std::string pfx, IndexCommon *indc);
void query_with_passage (IndexCommon *indc, Passage *query, PpScores *pps, uint32_t *ind, float *score);
Passage index_passage (IndexCommon *indc, bool update,
                       uint8_t *binary_passage, uint32_t len,
                       uint32_t uind);


#endif // __INDEX_H__

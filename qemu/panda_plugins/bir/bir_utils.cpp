
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


void index_this_passage_c(void *vpindc, void *vpindex, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) ;

void *invert_c(void *vpindc, void *vpindex) ;

void marshall_index_common_c(void *vpindc);

void marshall_index_c(void *vpindc, void *vpindex, char *file_pfx);    

void marshall_invindex_c(void *vpindc, void *vpinv, char *file_pfx) ;

void *unmarshall_preprocessed_scores_c (char *filename_pfx);

void query_with_passage_c (void *vpindc, void *vppassage, void *vppps, uint32_t *ind, float *score);

void *new_index_common_c(char *filename_prefix, uint32_t min_n_gram, uint32_t max_n_gram, uint32_t passage_len_bytes) ;

void *new_index_c() ;

void index_common_set_passage_len_bytes_c(void *vpindc, uint32_t passage_len_bytes);

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



///////////////////////////////////////////////////

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
    printf ("size=%d\n", (int) uind_to_psgs.size());
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

void spit_string_uint32_map ( std::map < std::string, uint32_t > & su32m ) {
    printf ("size=%d\n", (int) su32m.size());
    for ( auto &kvp : su32m ) {
        printf ("%s -> %d\n", kvp.first.c_str(), kvp.second );
    }
}

void spit_uint32_string_map ( std::map < uint32_t, std::string > & u32sm ) {
    printf ("size=%d\n", (int) u32sm.size());
    for ( auto &kvp : u32sm ) {
        printf ("%d -> %s\n", kvp.first, kvp.second.c_str() );
    }
}    

void spit_uint32_uint32_map ( std::map < uint32_t, uint32_t > & u32u32m ) {
    printf ("size=%d\n", (int) u32u32m.size());
    for ( auto &kvp : u32u32m ) {
        printf ("%d -> %d\n", kvp.first, kvp.second );
    }
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
    printf ("binary_to_uind is %d entries\n", (int) index->binary_to_uind.size());
    printf ("uind_to_passage [\n");
    printf ("size=%d\n", (int) index->uind_to_passage.size());
    for ( auto &kvp : index->uind_to_passage ) {
        printf ("uind = %d\n", (int) kvp.first);
        spit_passage(kvp.second);
    }
    printf ("uind_to_passage ]\n");
    printf ("passages [\n");
    printf ("size=%d\n", (int) index->passages.size());
    // iterate over passages
    for ( auto &kvp : index->passages ) {
        printf ("%d -> %d\n", (int) kvp.first, (int) kvp.second);
    }
    printf ("passages ]\n");
    printf ("Index ]\n");
}

void spit_docs_with_word(IndexCommon *indc, std::map < uint32_t, std::map < Gram, std::map < uint32_t, uint32_t > > > &docs_with_word) {
    printf ("docs_with_word [\n");
    printf ("size=%d\n", (int) docs_with_word.size());
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {   
        for ( auto &kvp : docs_with_word[n] ) {
            spit_gram_hex(kvp.first, n);
            printf (" : ");
            for ( auto &kvp2 : kvp.second ) {
                printf (" (%d,%d)", kvp2.first, kvp2.second);
            }
            printf ("\n");
        }
    }
    printf ("docs_with_word ]\n");
}


void spit_general_query(IndexCommon *indc, std::map < uint32_t, std::map < Gram, uint32_t > > &general_query ) {
    printf ("general_query [\n");
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("n=%d\n", n);
        for ( auto &kvp : general_query[n] ) {
            printf ("  ");
            spit_gram_hex(kvp.first, n);
            printf (" %d\n", kvp.second);
        }
    }
    printf ("general_query ]\n");
}


void spit_inv(IndexCommon *indc, InvIndex *inv) {
    printf ("InvIndex [\n");
    spit_docs_with_word(indc, inv->docs_with_word);
    // dont spit map_dw 
    printf ("total_count [\n");
    spit_uint32_uint32_map(inv->total_count);
    printf ("total_count ]\n");    
    spit_general_query(indc, inv->general_query);
    printf ("InvIndex ]\n");
}


///////////////////////////////////////////////////


// collect n-gram distributions for passage.  length len.  may contain nulls
Passage index_passage (IndexCommon *indc, bool update,
                       uint8_t *binary_passage, uint32_t len,
                       uint32_t uind) {
    Passage passage;
    passage.uind = uind;
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
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



/*
  Count n-grams for this binary blob (a passage).
  The lexicon and index both get updated.
*/
void index_this_passage(IndexCommon *indc, Index *index, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) {    
    // maintain map a from binary passages to ints
    std::string sb = std::string((const char *) binary_passage, len);
    uint32_t uind;
    if (index->binary_to_uind.find(sb) == index->binary_to_uind.end()) {
        uind = index->binary_to_uind.size();
        // this is a new passage, i.e., we haven't indexed this binary blob before
        if ((uind % 1000) == 0) {
            printf ("%d unique passages indexed.  %d passages observed\n", (int) uind, (int) index->passages.size());
        }
        index->binary_to_uind[sb] = uind;
        index->uind_to_passage[uind] = 
            index_passage(indc, /* updatelexicon = */ true, binary_passage, len, uind);        
        indc->num_uind = index->binary_to_uind.size();
    }
    else {
        // a passage we have indexed previously -- get unique id
        uind = index->binary_to_uind[sb];
    }       
    index->passages[passage_ind] = uind;
    // this is the total # of passages (not unique ones) indexed
    indc->num_passages ++;
    // keeps track of set of passages for this uind
    indc->uind_to_psgs[uind].insert(passage_ind);
}


//////////////////////////////////////////////////////////////////////

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

void marshall_uind_to_psgs(std::string &pfx, std::map < uint32_t, std::set < uint32_t > > &uind_to_psgs) {
    printf ("marshalling uind to psg set\n");
    std::string filename = pfx + ".uind_to_psgs";
    FILE *fp = fopen((char *) filename.c_str(), "w");
    uint32_t occ = uind_to_psgs.size();
    WU(occ);  
    for ( auto &kvp : uind_to_psgs ) {
        uint32_t uind = kvp.first;
        WU(uind);
        occ = kvp.second.size();
        WU (occ);
        for ( auto &el : kvp.second ) {
            WU(el);
        }
    }
    fclose(fp);
}

std::map < uint32_t, std::set < uint32_t > > unmarshall_uind_to_psgs(std::string pfx) {
    printf ("unmarshalling uind to psg set\n");
    std::string filename = pfx + ".uind_to_psgs";
    FILE *fp = fopen((char *) filename.c_str(), "r");
    uint32_t occ1;
    RU(occ1);
    std::map < uint32_t, std::set < uint32_t > > uind_to_psgs;
    for (uint32_t i=0; i<occ1; i++) {
        uint32_t uind;
        RU(uind);
        uint32_t occ2;
        RU (occ2);
        //       printf ("uind=%d occ2=%d\n", uind, occ2);
        for (uint32_t j=0; j<occ2; j++) {
            uint32_t psg;
            RU(psg);
            uind_to_psgs[uind].insert(psg);
        }
    }
    fclose(fp);
    return uind_to_psgs;
}


void marshall_index_common(IndexCommon *indc) {
    printf ("marshalling index_common\n");
    std::string pfx = indc->filename_prefix;
    std::string filename = pfx + ".indc";
    FILE *fp = fopen((char *) filename.c_str(), "w");
    WU(indc->min_n_gram);
    WU(indc->max_n_gram);
    WU(indc->passage_len_bytes);
    WU(indc->num_passages);
    WU(indc->num_uind);
    fclose(fp);
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("marshalling lexicon n=%d\n", n);
        marshall_lexicon(pfx + ".lexicon-" + std::to_string(n), indc->lexicon[n]);
    }
    marshall_uind_to_psgs(pfx, indc->uind_to_psgs);
    printf ("marshalling f2fp and fp2f\n");
    if (indc->filename_to_first_passage.size() == 0) {
        printf ("... which are empty so filling with something\n");
        indc->filename_to_first_passage[indc->filename_prefix] = 0;
        indc->first_passage_to_filename[0] = indc->filename_prefix;
    }
    marshall_string_uint32_map(pfx + ".f2fp", indc->filename_to_first_passage);
    marshall_uint32_string_map(pfx + ".fpf2", indc->first_passage_to_filename);
}  
  

void unmarshall_indc(const std::string pfx, IndexCommon *indc) {
    std::string filename = pfx + ".indc";
    FILE *fp = fopen((char *) filename.c_str(), "r");
    indc->filename_prefix = pfx;
    RU(indc->min_n_gram);
    RU(indc->max_n_gram);
    RU(indc->passage_len_bytes);
    RU(indc->num_passages);
    RU(indc->num_uind);
    fclose(fp);
}


// if uind_to_psgs is false, then we dont load that.  it can be slow
IndexCommon *unmarshall_index_common(const std::string pfx, bool uind_to_psgs) {
    IndexCommon *indc = new IndexCommon;
    unmarshall_indc(pfx, indc);
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("unmarshalling lexicon n=%d\n", n);
        indc->lexicon[n] = unmarshall_lexicon(pfx + ".lexicon-" + std::to_string(n), n);
    }
    if (uind_to_psgs) {
        indc->uind_to_psgs = unmarshall_uind_to_psgs(pfx);
    }
    indc->filename_to_first_passage = unmarshall_string_uint32_map(pfx + ".f2fp");
    indc->first_passage_to_filename = unmarshall_uint32_string_map(pfx + ".fpf2");
    return indc;
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
        
    
void marshall_index(IndexCommon *indc, Index *index) {
    std::string filename ;
    uint32_t occ = index->binary_to_uind.size();
    printf ("marshalling binary_to_uind occ=%d\n", (int) occ);
    std::string pfx = indc->filename_prefix;
    filename = indc->filename_prefix + ".b2u";
    FILE *fp = fopen((char *) filename.c_str(), "w");
    WU(occ);
    for ( auto &kvp : index->binary_to_uind ) {       
        WS(kvp.first);
        WU(kvp.second);
    }
    fclose(fp);
    occ = index->uind_to_passage.size();
    printf ("marshalling uind_to_passage occ=%d\n", (int) occ);
    filename = indc->filename_prefix + ".utp";
    fp = fopen((char *) filename.c_str(), "w");
    WU(occ);
    for ( auto &kvp : index->uind_to_passage ) {
        WU(kvp.first);
        Passage &passage = kvp.second;
        marshall_passage(passage, fp);
    }
    fclose(fp);
    occ = index->passages.size();
    printf ("marshalling passages to uind occ=%d\n", occ);
    filename = indc->filename_prefix + ".passages";
    fp = fopen((char *) filename.c_str(), "w");
    WU(occ);
    for (uint32_t i=0; i<occ; i++) {
        uint32_t passage_ind = index->passages[i];
        WU(passage_ind);
    }
    fclose(fp);
}


// only unmarshall passages if passages=true
Index *unmarshall_index(std::string pfx, IndexCommon *indc, bool passages) {
    Index *index = new Index;
    printf ("unmarshalling binary_to_uind\n");
    std::string filename;
    filename = indc->filename_prefix + ".b2u";
    FILE *fp = fopen((char *) filename.c_str(), "r");
    uint32_t occ;
    RU(occ);
    printf ("%d size\n", occ);
    for (uint32_t i=0; i<occ; i++) {
        std::string binary;
        uint32_t uind;
        RS(binary);
        RU(uind);
        index->binary_to_uind[binary] = uind;
    }
    fclose(fp);
    printf ("unmarshalling uind_to_passage \n");
    filename = indc->filename_prefix + ".utp";
    fp = fopen((char *) filename.c_str(), "r");
    RU(occ);
    printf ("%d size\n", occ);
    for (uint32_t i=0; i<occ; i++) {     
        uint32_t uind;
        RU(uind);
        index->uind_to_passage[uind] = unmarshall_passage(fp);
    }
    fclose(fp);
    if (passages) {
        printf ("unmarshalling passages \n");
        filename = indc->filename_prefix + ".passages";
        fp = fopen((char *) filename.c_str(), "r");
        RU(occ);
        printf ("%d size\n", occ);    
        for (uint32_t i=0; i<occ; i++) {
            uint32_t passage_ind;
            RU(passage_ind);
            index->passages[i] = passage_ind;
        }
        fclose(fp);
    }
    return index;
}
    

			      
// marshalls everything *except* the doc-word arrays
void marshall_invindex_min(IndexCommon *indc, InvIndex *inv) {
    std::string pfx = indc->filename_prefix;
    std::string filename;
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        marshall_gram_long_map(pfx + ".inv-map-" + std::to_string(n), inv->map_dw[n]);
        marshall_gram_uint32_map(pfx + ".gen-" + std::to_string(n), inv->general_query[n]);
    }
    marshall_uint32_uint32_map(pfx + ".total_count", inv->total_count);
}
 

// unmarshalls everything except the doc-word arrays
InvIndex *unmarshall_invindex_min(std::string pfx, IndexCommon *indc) {
    InvIndex *inv = new InvIndex;    
    std::string filename;
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {        
        inv->map_dw[n] = unmarshall_gram_long_map(pfx + ".inv-map-" + std::to_string(n));
        inv->general_query[n] = unmarshall_gram_uint32_map(pfx + ".gen-" + std::to_string(n));
    }
    inv->total_count = unmarshall_uint32_uint32_map(pfx + ".total_count");
    return inv;
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


void marshall_invindex(IndexCommon *indc, InvIndex *inv) {
    std::string pfx = indc->filename_prefix;
    std::string filename;
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        filename = pfx + ".inv-map-" + std::to_string(n);
        FILE *fpinvmap = fopen((char *) filename.c_str(), "w");
        uint32_t occ = indc->lexicon[n].grams.size();
        fwrite(&occ, sizeof(occ), 1, fpinvmap);
        filename = pfx + ".inv-" + std::to_string(n);
        FILE *fpinv = fopen((char *) filename.c_str(), "w");
        // create map_dw here
        for ( auto &gram : indc->lexicon[n].grams ) {           
            inv->map_dw[n][gram] = ftell(fpinv);      
            marshall_doc_word_fp(fpinv, inv->docs_with_word[n][gram]);
        }
        fclose(fpinv);
        fclose(fpinvmap);
    }
    // NB: have to do this last b/c otherwise invindex->map_dw not populated
    marshall_invindex_min(indc, inv);
}



void marshall_preprocessed_scores(IndexCommon *indc, PpScores *pps) {
    std::string pfx = indc->filename_prefix;
    std::string filename = pfx + ".pp";
    FILE *fp = fopen((char *) filename.c_str(), "w");
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
        pps->scorerow[gram].len = rowsize;
        pps->scorerow[gram].el = (Score *) malloc (sizeof (Score) * rowsize);
        uint32_t nn = fread((void *) pps->scorerow[gram].el, sizeof (Score), rowsize, fp);
        assert(nn==rowsize);
    }
    fclose(fp);
    printf ("done\n");
    return pps;
}                





// construct passage name from ind, using first_passage_to_filename
// passage_name assumed alloc big enough to fit filename-offset
std::string get_passage_name(IndexCommon *indc, uint32_t passage_ind, uint32_t *start_pos) {
    auto x = (indc->first_passage_to_filename.upper_bound(passage_ind));
    x--;
    std::string filename = x->second;
    uint64_t offset;
    if ((passage_ind % 2) == 0) {
        uint32_t num_chunks = passage_ind / 2;
        offset = num_chunks * indc->passage_len_bytes;
    }
    else {
        uint32_t num_chunks = (passage_ind - 1) / 2;
        offset = indc->passage_len_bytes/2 + num_chunks * indc->passage_len_bytes;
    }
    *start_pos = offset;
    return filename;
}



InvIndex *invert(IndexCommon *indc, Index *index) {
    int i;
    printf ("Inverting index\n");
    InvIndex *inv = new InvIndex;
    // iterate over *unique* passages in the index
    uint32_t ii=0;
    uint32_t tot = index->uind_to_passage.size();
    uint32_t i10 = tot / 10;
    for ( auto &kvp : index->uind_to_passage ) {
        if (ii > 0 && (ii % i10) == 0) {
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
                // shoudn't already have a count
                assert (inv->docs_with_word[pd.n][gram].find(passage.uind) == inv->docs_with_word[pd.n][gram].end());
                inv->docs_with_word[pd.n][gram][passage.uind] = count;
                inv->general_query[pd.n][gram] += count;
                inv->total_count[pd.n] += count;
            }
        }
    }
    return inv;
}     



static bool compare_scores (const Score & s1, const Score & s2) {
    return (s1.val > s2.val);
}


// query is a passage.  


Score *score = NULL;
/*
  query contains a passage
  scorepair is preprocessed score arrays. let n = scorepare[max_n_gram].first.  
  scorepair[max_n_gram].second is a c array of n Score structs 
  scorepair[max_n_gram].second[i].ind is a passage ind and .val is the preprocessed score to add for that psg.
*/ 
void query_with_passage (IndexCommon *indc, Passage *query, PpScores *pps, uint32_t *ind, float *best_score) {
    if (score == NULL) {
        score = (Score *) malloc (sizeof(Score) * indc->num_uind);
    }
    // clear the scores
    for (uint32_t i = 0; i < indc->num_uind; i++) {
        score[i].ind = i;
        score[i].val = 0.0;
    }
    // iterate over highest order ngrams in the "query"
    for (auto &kvp : query->contents[indc->max_n_gram].count)    {
        Gram gram = kvp.first;
        uint32_t gram_count = kvp.second;
        if (pps->scorerow.find(gram) == pps->scorerow.end()) {
            continue;
        }
        uint32_t rowsize = pps->scorerow[gram].len;
        assert (rowsize < indc->num_uind);
        Score *sp = pps->scorerow[gram].el;
        for (uint32_t i=0; i<rowsize; i++) {
            uint32_t uid = sp[i].ind; 
            if (uid >= indc->num_uind) {
                printf ("uid=%d num_uinq=%d\n", uid, indc->num_uind);
                assert (uid < indc->num_uind);
            }
            score[uid].val += gram_count * sp[i].val;
        }
    }
    // scale the scores
    float max_score = -10000.0;
    uint32_t argmax = 0;
    //    float min_score = 10000.0;
    //    uint32_t argmin = 0;
    for (uint32_t i = 0; i < indc->num_uind; i++) {
        score[i].val /= query->contents[indc->max_n_gram].total;
        if (score[i].val > max_score) {
            max_score = score[i].val;
            argmax = i;
        }
    }
    /*
    std::sort (score.begin (), score.end (), compare_scores);  
    for (uint32_t i=0; i<5; i++) {
        printf ("%d %d %.4f\n", i, score[i].ind, score[i].val);
        for ( auto &el : indc->uind_to_psgs[score[i].ind] ) {
            printf ("%d ", el);
        }
        printf ("\n");
    }
    
    printf ("min_score = %.5f\n", min_score);
    */
    *ind = argmax;
    *best_score = max_score;
}




////////////////////////////////////////////
// 
// C API

void index_this_passage_c(void *vpindc, void *vpindex, uint8_t *binary_passage, uint32_t len, uint32_t passage_ind) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    Index *index = reinterpret_cast<Index *> (vpindex);
    index_this_passage(indc, index, binary_passage, len, passage_ind);
}

void *invert_c(void *vpindc, void *vpindex) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    Index *index = reinterpret_cast<Index *> (vpindex);
    InvIndex *inv = invert(indc, index);
    return reinterpret_cast<void *> (inv);
}

void marshall_invindex_c(void *vpindc, void *vpinv, char *file_pfx) {
    InvIndex *inv = reinterpret_cast<InvIndex *> (vpinv);
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    marshall_invindex(indc, inv);
}

void marshall_index_c(void *vpindc, void *vpindex, char *file_pfx) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    Index *index = reinterpret_cast<Index *> (vpindex);
    marshall_index(indc, index);
}

void marshall_index_common_c(void *vpindc) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    marshall_index_common(indc);
}

void *unmarshall_preprocessed_scores_c (char *filename_pfx) {
    PpScores *pps = unmarshall_preprocessed_scores(std::string(filename_pfx));
    return reinterpret_cast <void *> (pps);
}

void query_with_passage_c (void *vpindc, void *vppassage, void *vppps, uint32_t *ind, float *score) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    Passage *passage = reinterpret_cast<Passage *>(vppassage);
    PpScores *pps = reinterpret_cast<PpScores *>(vppps);
    query_with_passage(indc, passage, pps, ind, score);
}

void *new_index_common_c(char *filename_prefix, 
                         uint32_t min_n_gram, uint32_t max_n_gram,
                         uint32_t passage_len_bytes) {
    IndexCommon *indc = new_index_common(std::string(filename_prefix),
                                         min_n_gram, max_n_gram, passage_len_bytes);
    return reinterpret_cast<void *> (indc);
}

void *new_index_c() {
    Index *index = new Index;
    return reinterpret_cast<void *> (index);
}

void index_common_set_passage_len_bytes_c(void *vpindc, uint32_t passage_len_bytes) {
    IndexCommon *indc = reinterpret_cast<IndexCommon *> (vpindc);
    indc->passage_len_bytes = passage_len_bytes;
}


extern "C" {
    
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
    
}

#include "index.hpp"
#include<map>
#include<set>

std::map < std::string, double > starttime;


// returns sub-gram starting at pos of len bytes
static inline Gram igramsub(Gram g, uint32_t pos, uint32_t len) {
    uint64_t mask = (0xffffffffffffffff >> (64 - len * 8)) << (8 * pos);
    return (((uint64_t) g) & mask) >> (8 * pos);
}



double getsecs() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return ((double) time.tv_sec) + ((double) time.tv_usec) / 1000000.0;
}

void timer_start(std::string timername) {
    starttime[timername] = getsecs();
}


float timer_stop(std::string timername) {
    if (starttime.count(timername) != 0) {
        float secs = getsecs() - starttime[timername];
        printf ("time for [%s] = %.5f\n", timername.c_str(), secs);
        return secs;
    }
    return -1.0;
}


bool pdice (float prob_yes) {
    if ((((float) (rand ())) / RAND_MAX) < prob_yes) 
        return true;    
    else
        return false;
}





int main (int argc, char **argv) {


    if (argc !=3) {
        printf ("usage: inv_pfx max_row_length\n");
        printf ("inv_pfx is file pfx for inv index containing counts\n");
        exit(1);
    }
    std::string pfx = std::string(argv[1]);
    uint32_t max_row_length = atoi(argv[2]);

    IndexCommon *indc = unmarshall_index_common(pfx, false);
    InvIndex *inv = unmarshall_invindex_min(pfx, indc);
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("unmarshalling inv %d\n", n);
        std::string filename;
        filename =pfx + ".inv-" + std::to_string(n);
        FILE *fp = fopen((const char *) filename.c_str(), "r");
        for ( auto gram : indc->lexicon[n].grams ) {            
            inv->docs_with_word[n][gram] = unmarshall_doc_word_fp(fp, inv, n, gram);
        }
    }
    printf ("done unmarshalling inv\n");

    std::vector < float > scoring_params(indc->max_n_gram + 1);
    for (uint32_t n = 0; n <= indc->max_n_gram; n++) {
        scoring_params[n] = 1.0 / (n + 2);
    }

    std::map < uint32_t, float > sc;
    std::set < float > pp;

    // iterate over grams with max n
    uint32_t tot = indc->lexicon[indc->max_n_gram].grams.size();
    uint32_t ii = 0;

    PpScores *pps = new PpScores;
    //    pps->scorerow = std :: map < Gram, ScoreRow > ();
    
    //   timer_start("a");
    // iterate over max-n grams 
    for ( auto mgram : indc->lexicon[indc->max_n_gram].grams ) {        
        // e.g. if max n gram is 5-gram, 
        // this might be "abcde"
        if ((ii%(tot/10)) == 0) {
            printf ("ii = %d of %d\n", ii, tot);
        }
        ii ++;
        // since gram is inv->max_n_gram bytes long,
        // this is the last byte
        // e.g. the unigram "e"
        Gram g = igramsub(mgram, indc->max_n_gram - 1, 1);               
        // p(q|G) 
        float pg = ((float) inv->general_query[1][g]) / inv->total_count[1];
        // clear per-passage for-this-q scores        
        // here we compute the numerator in Eq 2, 
        float is = scoring_params[0] * pg;
        // printf ("is = %.3f\n", is);
        std::map < uint32_t, float > pppqs;
        // iterate over psgs that contain the max n gram
        for (uint32_t n = indc->min_n_gram; n <= indc->max_n_gram; n++)  {
            float w = scoring_params[n];
            // this is the ngram for this n that ends in the unigram g (and includes it)           
            Gram ngram = igramsub(mgram, indc->max_n_gram - n, n);
            // prev_part  is everything but g
            // n=5, this is "abcd"           
            Gram prev_part = igramsub(ngram, 0, n-1);
            for (auto &kvp : inv->docs_with_word[indc->max_n_gram][mgram]) {
                uint32_t passage_ind = kvp.first;
                // and this is the count for ngram in passage_ind
                uint32_t c_ngram = inv->docs_with_word[indc->max_n_gram][mgram][passage_ind];
                // e.g. iterate over psgs that have the max_n_gram           
                float denom = indc->passage_len_bytes;
                if (n > 1) {
                    denom = inv->docs_with_word[n-1][prev_part][passage_ind];
                }
                float p = ((float) c_ngram) / denom;
                if (pppqs.find(passage_ind) == pppqs.end()) {
                    pppqs[passage_ind] = is;
                }
                pppqs[passage_ind] += w * p;                
            }
        }
        uint32_t rowsize = pppqs.size();
        pps->scorerow[mgram].len = rowsize;
        pps->scorerow[mgram].el = (Score *) malloc(sizeof(Score) * rowsize);
        int i=0;
        for ( auto &kvp : pppqs ) {
            //            printf ("ppqs %d %.3f\n", kvp.first, kvp.second);
            pps->scorerow[mgram].el[i].ind = kvp.first;
            pps->scorerow[mgram].el[i].val = log(kvp.second / pg);
            //            printf ("ind=%d val=%.3f\n", pps->scorerow[mgram].el[i].ind, pps->scorerow[mgram].el[i].val);
            i++;
        }        
    }
    printf ("done precomputing\n");
    marshall_preprocessed_scores(indc, pps);
    printf ("done marshalling\n");

}

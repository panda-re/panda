
extern "C" {
    
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
    
}

#include "index.hpp"
#include<map>
#include<set>

std::map < std::string, double > starttime;

bool debug = false;

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


double timer_stop(std::string timername) {
    if (starttime.count(timername) != 0) {
        double secs = getsecs() - starttime[timername];
        printf ("time for [%s] = %.5f\n", timername.c_str(), secs);
        return secs;
    }
    return -1.0;
}


bool pdice (double prob_yes) {
    if ((((double) (rand ())) / RAND_MAX) < prob_yes) 
        return true;    
    else
        return false;
}




extern uint32_t max_row_length;
double alpha;

int main (int argc, char **argv) {


    if (argc !=6) {
        printf ("usage: inv_pfx max_row_length alpha\n");
        printf ("inv_pfx is file pfx for inv index containing counts\n");
        printf ("weight scheme version (0 or 1)\n");
        printf ("alpha: sharpness of weightings on unigrams vs. whatever\n");
        printf ("min_sc: discard preprocessed scores below this range\n");
        exit(1);
    }
    std::string pfx = std::string(argv[1]);
    max_row_length = atoi(argv[2]);
    uint32_t weight_scheme = atoi(argv[3]);
    alpha = atof(argv[4]);
    double min_sc = atoi(argv[5]);


    printf ("pfx = %s\n", pfx.c_str());
    printf ("max_row_length = %d\n", max_row_length);
    printf ("weight_scheme = %d\n", weight_scheme);
    printf ("alpha = %.3f\n", alpha);
    printf ("min score %.3f \n", min_sc);
    
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

    std::vector < double > scoring_params(indc->max_n_gram + 1);
    double sum = 0.0;
    for (uint32_t n = 0; n <= indc->max_n_gram; n++) {
        if (weight_scheme == 0) {
            scoring_params[n] = pow(1.0 / (n + 1), alpha);
        }
        else if (weight_scheme == 1) {
            scoring_params[n] = pow((n + 1), alpha);
        }
        else {
            assert (1==0);
        }
        sum += scoring_params[n];
    }
    for (uint32_t n = 0; n <= indc->max_n_gram; n++) {
        scoring_params[n] /= sum;
        printf ("scoring_param %d = %.4f\n", n, scoring_params[n]);
    }

    std::map < uint32_t, double > sc;
    std::set < double > pp;

    PpScores *pps = new PpScores;
    uint32_t num_filtered = 0;
    uint32_t num_total = 0;
    for (uint32_t n = indc->max_n_gram; n >=indc->min_n_gram; n --) {
        printf ("Precomputing scores for n=%d\n", n);
        uint32_t ii = 0;                
        uint32_t tot = indc->lexicon[n].grams.size();
        // iterate over grams for this value of n
        for ( auto g : indc->lexicon[n].grams ) {        
            if (debug) {
                printf ("Precomputing scores for ");
                spit_gram_hex(stdout, g, n);
                printf ("\n");
            }
            // case study.  say n = 4 and g = 'abcd'
            if ((ii%(tot/10)) == 0) printf ("ii = %d of %d\n", ii, tot); 
            ii ++;
            pps->scorerow[n][g].len = inv->docs_with_word[n][g].size();
            pps->scorerow[n][g].el = (Score *) malloc(sizeof(Score) * pps->scorerow[n][g].len);
            // iterate over psgs that contain g
            uint32_t j = 0;
            for ( auto &kvp : inv->docs_with_word[n][g] ) {
                uint32_t passage_ind = kvp.first;
                if (debug)  printf ("  psg=%d\n", passage_ind);
                // and now iterate 1..n to compute numerator & denominator for Eq 2.
                double numerator = 0.0;
                double denominator = 0.0;
                for (uint32_t nn = indc->min_n_gram; nn <= n; nn++) {
                    // e.g. if whole_gram = 'abc' then prev_part = 'ab'
                    Gram whole_gram = igramsub(g, 0, nn);
                    // compute per-passage probability, ppp
                    // and in-general probability, igp
                    uint32_t ppp_count_whole_gram = inv->docs_with_word[nn][whole_gram][passage_ind];
                    uint32_t igp_count_whole_gram = inv->general_query[nn][whole_gram];
                    if (debug) {
                        printf ("    whole_gram ");
                        spit_gram_hex(stdout, whole_gram, nn);
                        printf (" c|p=%d c|g=%d\n", ppp_count_whole_gram, igp_count_whole_gram);
                    }
                    uint32_t ppp_count_prev_part, igp_count_prev_part;                   
                    double ppp, igp;
                    if (nn > indc->min_n_gram) {                        
                        Gram prev_part; 
                        prev_part = igramsub(g, 0, nn-1);
                        ppp_count_prev_part = inv->docs_with_word[nn-1][prev_part][passage_ind];
                        igp_count_prev_part = inv->general_query[nn-1][prev_part];
                        if (debug) {
                            printf ("    prev_part ");
                            spit_gram_hex(stdout, prev_part, nn-1);
                            printf (" c|p=%d c|g=%d\n", ppp_count_prev_part, igp_count_prev_part);
                        }
                        ppp = ((double) ppp_count_whole_gram) / ppp_count_prev_part;
                        igp = ((double) igp_count_whole_gram) / igp_count_prev_part;
                    }
                    else {
                        ppp = ((double) ppp_count_whole_gram) / indc->passage_len_bytes;
                        igp = ((double) igp_count_whole_gram) / inv->total_count[nn];
                    }
                    if (debug) printf ("ppp=%.4f  igp=%.4f\n", ppp, igp);
                    numerator += scoring_params[nn] * ppp;
                    denominator += scoring_params[nn] * igp;
                    if (debug) {
                        printf ("numerator += %.4f\n", scoring_params[nn] * ppp);
                        printf ("denominator += %.4f\n", scoring_params[nn] * igp);
                    }                    
                }
                double score = log(numerator / denominator);
                //                printf ("score = %.4f\n", score);
                num_total++;
                if (score >= min_sc) {
                    pps->scorerow[n][g].el[j] = {passage_ind, log(numerator / denominator)};
                    if (debug) {
                        printf ("n=%d g=", n);
                        spit_gram_hex(stdout, g,n);
                        printf (" psg=%d sc=%.4f\n", passage_ind, pps->scorerow[n][g].el[j].val);
                        printf ("\n");
                    }
                    j++;
                }
                else {
                    num_filtered++;
                }                    
            }
        }
    }


    printf ("score range retained %.3f\n", ((float) (num_total - num_filtered)) / num_total);

    printf ("done precomputing\n");
    marshall_preprocessed_scores(indc, pps);
    printf ("done marshalling\n");

}

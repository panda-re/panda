/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

extern "C" {

#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "../taint/taint_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"



#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include "../taint/taint_processor.h"
#include "panda_common.h"

#include "index.hpp"


#ifdef CONFIG_SOFTMMU



// globals
uint32_t minn, maxn;
InvIndex inv;
std::vector < float > *scoring_params;
std::vector < Score > *score ;
std::vector < FILE * > * fpinv ;


bool compare_scores (const Score & s1, const Score & s2) {
    return (s1.val > s2.val);
}


extern uint32_t max_row_length;


extern "C" {
#include <sys/time.h>
}


struct timeval time1, time2;

void timer_start() {
    gettimeofday(&time1, NULL);
}


float timer_stop() {
    gettimeofday(&time2, NULL);
    float secs = time2.tv_sec - time1.tv_sec;
    secs += ((float) (time2.tv_usec - time1.tv_usec)) / 1000000.0;
    return secs;
}


// memoized inv
// invm[n][g][p] is counts for n - gram g in passage p 
std::map < uint32_t, std::map < Gram, std:: map < uint32_t, uint32_t > > > invm;

std::map < uint32_t, uint32_t > unmarshall_row(FILE *fp, InvIndex &inv, uint32_t n, Gram g) {
    if ((invm.count(n) == 0) || (invm[n].count(g) == 0)) {
        invm[n][g] = unmarshall_doc_word_fp(fp, inv, n, g);
    }
    return invm[n][g];
}


/*

  Our score is 

  P(PSG is RELEVANT | Q) 
    
  where PSG is a passage, and Q is a query

  By Bayes' rule,

.                            P(Q | PSG is RELEVANT) * P(PSG is RELEVANT)
.  P(PSG is RELEVANT | Q) = ----------------------------------------------
.                                              P(Q)

  We are using this to rank passages, so P(Q) doesnt matter.  And we don't have a prior on P(PSG is RELEVANT) so really 
  our score is just

  P(Q | PSG is RELEVANT)

  which we compute, under an independence assumption, as
    

  P(Q | PSG is RELEVANT)  
.      ~= Prod(q in Q) P(q | PSG is R)

.      ~= Prod(q in Q) ( 
.                           a0 * P(q|G) 
.                        +  a1 * P(q|PSG)
.                        +  a2 * P(q|q_,PSG)  
.                        +  a3 * P(q|q_,q__,PSG)  
.                        +  ...  (higher order n-grams, if desired)
.                      )
.        (Eq 1)

  where we have used a mixture model for P(q | PSG is R)
    
  a0, a1, a2, etc are weights that sum to 1 

  q is the individual parts of Q.  Here, the bytes in the passage, in sequence.

  P(q|G) is probability of q, generally.  
  That is, approximately counts(q in corpus) / (sum over q (counts(q in corpus)))

  P(q|PSG) is probability of q in the passage in question, that is 
  counts(q in PSG) / length of PSG.  This is a unigram or n=1 gram probability.

  P(q|q_,PSG) this is the probability of q given that q_ precedes it, in PSG. 
   This is computed as

  counts(q_,q in PSG) / counts(q_ in PSG). 

  That numerator is the number of times q follows q_ in the passage.  
  Thus, if *every* time we see q in PSG it follows q_, P(q|q_,PSG) will be 
  1 which is what we want.  This is the bigram or n=2 probability
    
  P(q|q_,q__,PSG) this is the probability of q given that q_ precedes it and q__ precedes q_.  
  This we approximate similar to P(q|q_,PSG) as counts(q__,q_,q in PSG) / counts(q__,q_ in PSG).
  This is the trigram or n=3 probability

  Higher-order n-gram probabilities are similar


  Now consider the product in Eq 1

  P(Q | PSG is R) = Prod(q in Q) P(q | PSG is R)

  The problem here is that this is a product of lots of small things and so we'll just get 0 given computer arithmetic. 
  So we'll compute a likelihood ratio and move to log domain.  Our product becomes a sum

   
.       / P(Q | PSG is R) \                         / P(q | PSG is R) \
.  log | ----------------  |   ~=  Sum(q in Q) log |  ---------------  |
.       \       P(Q)      /                         \      P(q|G)     /
 


  
*/


std::map < uint32_t, uint32_t > row_sizes;

// query is a passage.  
// score is 1-d array, one item for each passage in the index
void query_with_passage (Passage & query)  
{
    /*
    GramPsgCounts ngram_row;
    ngram_row.size = 0;
    ngram_row.max_size = 0;
    ngram_row.counts = NULL;
    */

    std::vector < float >pppqs = std::vector < float >(inv.num_passages);
    std::vector < uint32_t > sc = std::vector < uint32_t > (inv.num_passages);

    for (uint32_t i = 0; i < inv.num_passages; i++) {
        (*score)[i].ind = i;
        (*score)[i].val = 0.0;
        sc[i] = 0;
    }

    // iterate over highest order ngrams
    for (auto &kvp : query.contents[inv.max_n_gram].count)    {
        // e.g., if inv.max_n_gram = 5 this might be the three bytes "abcde"
        Gram gram = kvp.first;
        // e.g. count("abcde" in query)
        uint32_t gram_count = kvp.second;
        // since gram is inv.max_n_gram bytes long,
        // this is the last byte, i.e. the unigram "e"
        Gram g = gramsub(gram, inv.max_n_gram - 1, 1);               
        // p(q|G) 
        float pg = ((float) inv.general_query[1][g]) / inv.total_count[1];
        // clear per-passage for-this-q scores        
 
       for (uint32_t i = 0; i < inv.num_passages; i++) 	{
            pppqs[i] = (*scoring_params)[0] * pg;
        }     
       for (uint32_t n = inv.min_n_gram; n <= inv.max_n_gram; n++) 	{
            // this is the ngram for this n that ends in the unigram g (and includes it)
            Gram ngram = gramsub(gram, inv.max_n_gram - n, n);
            std::map < uint32_t, uint32_t > ngram_row = unmarshall_row ((*fpinv)[n], inv, n, ngram);            
            Gram prev_part;
            std::map < uint32_t, uint32_t > prev_part_dw;
            if (n != 1) {
                // this is everything but the last byte of ngram
                // e.g. in this case it would be, for n=5, "abcd"
                prev_part = gramsub(ngram, 0, n-1);
                prev_part_dw = unmarshall_row((*fpinv)[n-1], inv, n-1, prev_part);
            }
            float w = (*scoring_params)[n];
            // e.g. iterate over psgs that have the ngram            
            if (ngram_row.size() < max_row_length) {
                for ( auto &kvp : ngram_row ) {
                    uint32_t passage_ind = kvp.first;
                    uint32_t c_ngram = kvp.second;                    
                    float denom;
                    if (n == 1) {
                        denom = inv.passage_len_bytes; 
                    }
                    else  {
                        // c("b" in passage_ind), where "b" is prev_part 
                        denom = prev_part_dw[passage_ind];
                    }
                    float p = ((float) c_ngram) / denom;
                    pppqs[passage_ind] += w * p;
                }
            }
            // now divide each of those per-query-per-passage scores 
            // by p(q|G), take log, and accumulate result 
            // into per-passage score
            
            for (uint32_t i = 0; i < inv.num_passages; i++)   {
                // nb: gram_count is right thing to multiply by
                // if we multiplied by c(q|psg) we'd be overcounting
                (*score)[i].val += gram_count * (log (pppqs[i] / pg));
                //              (*score)[i].val += gram_count * pppqs[i];
            }
              
        }			// iterate over n
    }				// iterate over highest-order ngrams
    // scale the scores
    for (uint32_t i = 0; i < inv.num_passages; i++) {
        (*score)[i].val /= query.contents[inv.max_n_gram].total;
    }
    

    // sort the scores
    std::sort ((*score).begin (), (*score).end (), compare_scores);
}



bool pdice (float prob_yes) {
    if ((((float) (rand ())) / RAND_MAX) < prob_yes) 
        return true;    
    else
        return false;
}


float pdice_prob = 1.0;

// cache of binary -> top ranked psg 
// indexed by asid, then by pc

std::map < uint32_t, std::map < uint32_t, std::string > >  bircache;


int bir_before_block_exec(CPUState *env, TranslationBlock *tb) {

    //    float sec;

    //      if (tb->pc <= 0x500000 && tb->size > 16) {
    //if (tb->size > 16 && pdice(pdice_prob)) { 
    if ((tb->size > 16) && (tb->pc & 0xf000000000000000)) {
        
        //    if ((tb->pc > 0x1000000) && pdice(0.99) && tb->size>8) {
        target_ulong asid = panda_current_asid(env);
        //        printf ("pc=0x" TARGET_FMT_lx " len=%d \n", tb->pc, tb->size);
        
        if ((bircache.count(asid) != 0) && (bircache[asid].count(tb->pc) != 0)) {
            // its in the cache
            printf ("pc=0x" TARGET_FMT_lx " len=%d  ", tb->pc, tb->size);
            printf ("bir cache --  %s \n", bircache[asid][tb->pc].c_str());
        }
        else {
            // not in cache
            
            uint8_t buf[4096];
            uint32_t len = 4096;
            if (tb->size < len) {
                len = tb->size;
            }
            
            
            panda_virtual_memory_rw(env, tb->pc, (uint8_t *) buf, len, 0);    
            
            //            timer_start();
            Passage  passage = index_passage (inv.lexicon,
                                              /* update_lexicon = */ false,
                                              inv.min_n_gram, inv.max_n_gram,
                                              buf, len,
                                              /* note: we dont really care about passage ind */
                                              /* passage_ind = */ 0xdeadbeef);
            
            //            float sec;
            //            sec = timer_stop();
            //            printf ("%.5f sec to index_passage\n", sec);
            
            
            //      timer_start();
            query_with_passage (passage) ;
            //            sec = timer_stop();
            //            printf ("%.5f sec to query_with_passage\n", sec);
            
            printf ("pc=0x" TARGET_FMT_lx " len=%d  ", tb->pc, tb->size);
            if ( (*score)[0].val > 20 ) {
                uint32_t the_offset;
                const char *the_filename = get_passage_name(inv, (*score)[0].ind, &the_offset);            
                char the_psgname[1024];
                sprintf(the_psgname, "%s-%d", the_filename, the_offset);
                bircache[asid][tb->pc] = std::string(the_psgname);
                printf ("bir -- %.3f %s\n", (*score)[0].val, the_psgname);
            }      
            else {
                printf ("bir -- %.3f unknown\n", (*score)[0].val);
                bircache[asid][tb->pc] = "unknown";
            }
            
        /*           
            for (int j=0; j<2; j++) {
                uint32_t the_offset;       
                const char *the_filename = get_passage_name(inv, (*score)[j].ind, &the_offset);            
                char the_psgname[1024];
                sprintf(the_psgname, "%s-%d", the_filename, the_offset);
                if (j==0) {
                    if ((*score)[j].val > 20) {
                        bircache[asid][tb->pc] = std::string(the_psgname);
                    }
                    else {
                        bircache[asid][tb->pc] = std::string("not found in index");
                        printf ("bir -- not found in index\n");
                        //                        break;
                    }
                }
                printf ("  %d %.3f bir:%s-%d\n", j, (*score)[j].val, the_filename, the_offset);
            }
            */
        
        }
        
    }

    /*
    sec = timer_stop();
    printf ("%.8f sec to bir\n", sec);
    */

    return 0;
}

#endif 

bool init_plugin(void *self) {
    

#ifdef CONFIG_SOFTMMU

    panda_arg_list *args = panda_get_args("bir");
    if (args != NULL) {
        int i;
        char *invpfx = NULL;
        for (i = 0; i < args->nargs; i++) {
            printf ("arg=%s val=%s\n", args->list[i].key, args->list[i].value);
            if (0 == strncmp(args->list[i].key, "invpfx", 5)) {
                invpfx = args->list[i].value;
            } else if (0 == strncmp(args->list[i].key, "minn", 4)) {
                minn = atoi(args->list[i].value);                
            } else if (0 == strncmp(args->list[i].key, "maxn", 4)) {
                maxn = atoi(args->list[i].value);            
            } else if (0 == strncmp(args->list[i].key, "max_row_length", 14)) {
                max_row_length = atoi(args->list[i].value);
            } else if (0 == strncmp(args->list[i].key, "pdice", 5)) {
                pdice_prob = atof(args->list[i].value);
            }
        }
        printf ("minn = %d\n", minn);
        printf ("maxn = %d\n", maxn);
        printf ("max_row_length = %d\n", max_row_length);
        printf ("pdice_prob = %0.8f\n", pdice_prob);

        if (invpfx != NULL) {                
            inv = unmarshall_invindex_min (invpfx);

            //            spit_inv_min(inv);

            // weight for general_query = scoring_param[0] = 1/2
            // weight for n=1 is 1/3
            // weight for n=2 is 1/4
            // etc
            scoring_params = new std::vector < float > (inv.max_n_gram + 1);
            for (uint32_t n = 0; n <= inv.max_n_gram; n++) {
                (*scoring_params)[n] = 1.0 / (n + 2);
            }
            score = new std::vector < Score > (inv.num_passages);
            // open up all the inv files
            fpinv = new std::vector < FILE * >(inv.max_n_gram + 1);
            for (uint32_t n = inv.min_n_gram; n <= inv.max_n_gram; n++)   {
                // the inv index for this n, i.e. list of doc/count pairs for grams of this n
                char filename[65535];
                sprintf (filename, "%s.inv-%d", inv.filename_prefix.c_str (), n);
                (*fpinv)[n] = fopen (filename, "r");
            }
            
            panda_cb pcb;
            pcb.before_block_exec = bir_before_block_exec;
            panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
            

            return true;
        }
    }

#endif

    return false;
}

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

std::map < Gram, std::pair < uint32_t, Score * > > scorepair;
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


std::map < std::string, double > starttime;

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

float *pppqs= NULL;

/*
 * if we precompute (or memo-ize)
 * 
 *                                    /  a0 * P(q|G) + a1 * P(q|PSG) + a2 * P(q|q_,PSG) + a3 * P(q|q_,q__,PSG) + ... \
 *  sc[max_gram][passage_ind] = log |  ----------------------------------------------------------------------------- |
 *                                   \                                  P(q|G)                                      /
 *  
 *  where max_gram is the highest-order n-gram in the index,
 *  passage_ind is index for PSG
 *  q is the final byte in max_gram,
 *  q_ is the 2nd-to-last byte ...
 *  q__ is the 3rd-to-last byte ...
 *
 *  Call this Eq 2.  
 *
 *  Given the, score[psg] = sum (over max_gram in Q) sc[max_gram][psg]
 */

std::map < Gram, std::map < uint32_t, float > > sc;


// query is a passage.  
// score is 1-d array, one item for each passage in the index
static inline uint32_t query_with_passage (Passage & query)  
{
    if (pppqs == NULL) {
        pppqs = (float *) malloc(sizeof(float) * inv.num_passages);
    }
    for (uint32_t i = 0; i < inv.num_passages; i++) {
        (*score)[i].ind = i;
        (*score)[i].val = 0.0;
    }
    // iterate over highest order ngrams
    float max_score = -10000.0;
    uint32_t argmax = 0;
    for (auto &kvp : query.contents[inv.max_n_gram].count)    {
        // e.g., if inv.max_n_gram = 5 this might be the three bytes "abcde"
        Gram gram = kvp.first;
        // e.g. count("abcde" in query)
        uint32_t gram_count = kvp.second;
        uint32_t rowsize = scorepair[gram].first;
        Score *sp = scorepair[gram].second;
        for (uint32_t i=0; i<rowsize; i++) {
            uint32_t psgid = sp[i].ind;
            (*score)[psgid].val += gram_count * sp[i].val;
        }
    }
    // scale the scores
    for (uint32_t i = 0; i < inv.num_passages; i++) {
        (*score)[i].val /= query.contents[inv.max_n_gram].total;
        if ((*score)[i].val > max_score) {
            max_score = (*score)[i].val;
            argmax = i;
        }
    }        
    // sort the scores
    //    std::sort ((*score).begin (), (*score).end (), compare_scores);
    return argmax;
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

float sec;

int bir_before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (tb->size > 16) {         
        target_ulong asid = panda_current_asid(env);        
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
            Passage  passage = index_passage (inv.lexicon,
                                              /* update_lexicon = */ false,
                                              inv.min_n_gram, inv.max_n_gram,
                                              buf, len,
                                              /* note: we dont really care about passage ind */
                                              /* passage_ind = */ 0xdeadbeef);
            int argmax = query_with_passage (passage) ;
            printf ("pc=0x" TARGET_FMT_lx " len=%d  ", tb->pc, tb->size);
            if ( (*score)[argmax].val > 5.6 ) {
                uint32_t the_offset;
                const char *the_filename = get_passage_name(inv, (*score)[argmax].ind, &the_offset);            
                char the_psgname[1024];
                sprintf(the_psgname, "%s-%d", the_filename, the_offset);
                bircache[asid][tb->pc] = std::string(the_psgname);
                printf ("bir -- %.3f %s\n", (*score)[argmax].val, the_psgname);
            }      
            else {
                printf ("bir -- %.3f unknown\n", (*score)[argmax].val);
                bircache[asid][tb->pc] = "unknown";
            }
        }        
    }
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
            } else if (0 == strncmp(args->list[i].key, "max_row_length", 14)) {
                max_row_length = atoi(args->list[i].value);
            } else if (0 == strncmp(args->list[i].key, "pdice", 5)) {
                pdice_prob = atof(args->list[i].value);
            }
        }
        printf ("max_row_length = %d\n", max_row_length);
        printf ("pdice_prob = %0.8f\n", pdice_prob);
        if (invpfx != NULL) {                
            scorepair = unmarshallPreprocessedScores(invpfx);
            inv = unmarshall_invindex_min (invpfx);
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

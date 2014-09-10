


extern "C" {

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include "my_mem.h"

}

#include "index.hpp"
#include <chrono>

bool
compare_scores (const Score & s1, const Score & s2) {
    return (s1.val > s2.val);
}


bool
compare_count_pairs (const CountPair & s1, const CountPair & s2) {
    return (s1.count > s2.count);
}

extern uint32_t max_row_length;

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
void query_with_passage (InvIndex & inv,
                         std::vector < FILE * >fpinv,
                         Passage & query,
                         std::vector < float >&par,
                         std::vector < Score > &score,
                         uint32_t min_n, uint32_t max_n)  
{
    GramPsgCounts ngram_row;
    ngram_row.size = 0;
    ngram_row.max_size = 0;
    ngram_row.counts = NULL;

    GramPsgCounts ppngram_row;
    ppngram_row.size = 0;
    ppngram_row.max_size = 0;
    ppngram_row.counts = NULL;


    std::vector < float >pppqs = std::vector < float >(inv.num_passages);
    std::vector < uint32_t > sc = std::vector < uint32_t > (inv.num_passages);

    for (int i = 0; i < inv.num_passages; i++) {
        score[i].ind = i;
        score[i].val = 0.0;
        sc[i] = 0;
    }

    // iterate over highest order ngrams
    for (auto &kvp : query.contents[inv.max_n_gram].count)    {
        // e.g., if inv.max_n_gram = 3 this might be the three bytes "abc"
        Gram gram = kvp.first;
        // e.g. count("abc" in query)
        uint32_t gram_count = kvp.second;
        // since gram is inv.max_n_gram bytes long,
        // this is the last byte, i.e. the unigram
        // e.g. "c"
        Gram g = gramsub(gram, inv.max_n_gram - 1, 1);               
        // p(q|G) 
        float pg = ((float) inv.general_query[1][g]) / inv.total_count[1];
        // clear per-passage for-this-q scores        
        for (int i = 0; i < inv.num_passages; i++) 	{
            pppqs[i] = par[0] * pg;
        }     
        for (int n = min_n; n <= max_n; n++) 	{
            // this is the ngram for n
            // inv.max_n_gram = 3
            // n=1, we take substring of length 1 starting at pos=2
            // n=2, we take substring of length 2 starting at pos=1
            // n=3, we take substring of length 3 starting at pos=0
            // e.g. for n=2, this would be "bc"
            Gram ngram = gramsub(gram, inv.max_n_gram - n, n);
            int res = unmarshall_row_fp (fpinv[n], inv, n, ngram, ngram_row);            
            if (res == 0) {
                // row too long
                continue;
            }
            Gram prev_part;
            std::map < uint32_t, uint32_t > prev_part_dw;
            if (n > 1) {
                // this is everything but the last byte of ngram
                // e.g. in this case it would be "b"
                Gram prev_part = gramsub(ngram, 0, n-1);
                prev_part_dw = unmarshall_doc_word_fp(fpinv[n-1], inv, n-1, prev_part);
            }
            float w = par[n];
            // e.g. iterate over psgs that have bigram "bc"
            if (ngram_row.size < max_row_length) {
                //	  printf ("row_size = %d\n", ngram_row.size);
                //	  row_sizes[ngram_row.size] ++;
                for (int i = 0; i < ngram_row.size; i++) {
                    uint32_t passage_ind = ngram_row.counts[i].passage_ind;
                    // c("bc" in passage_ind)
                    uint32_t c_ngram = ngram_row.counts[i].count;
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
            
              for (int i = 0; i < inv.num_passages; i++)   {
                  // nb: gram_count is right thing to multiply by
                  // if we multiplied by c(q|psg) we'd be overcounting
                  score[i].val += gram_count * (log (pppqs[i] / pg));
                  //              score[i].val += gram_count * pppqs[i];
              }
              
        }			// iterate over n
    }				// iterate over highest-order ngrams
    // scale the scores
    // sort the scores
    std::sort (score.begin (), score.end (), compare_scores);
}



int pdice (float prob_yes) {
    if ((((float) (rand ())) / RAND_MAX) < prob_yes)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

std::vector < std::string > files = {
    "/mnt/qcow/Windows/System32/ntoskrnl.exe",
};

int main (int argc, char **argv) {

    if (argc != 7)     {
        printf ("usage: br inv_pfx num_tests prob_corrupt min_n max_n\n");
        exit (1);
    }

    char *    filename_prefix = argv[1];
    uint32_t  num_tests = atoi (argv[2]);
    float     prob_corrupt = atof (argv[3]);
    uint32_t  min_n = atoi (argv[4]);
    uint32_t  max_n = atoi (argv[5]);
    max_row_length  = atoi(argv[6]);

    auto t1 = std::chrono::high_resolution_clock::now();

    InvIndex  inv = unmarshall_invindex_min (filename_prefix);
    std::vector < float >  scoring_params = std::vector < float >(inv.max_n_gram + 1);
    // weight for general_query = scoring_param[0] = 1/2
    // weight for n=1 is 1/3
    // weight for n=2 is 1/4
    // etc
    for (int n = 0; n <= inv.max_n_gram; n++) {
        scoring_params[n] = 1.0 / (n + 2);
    }
    
    std::vector < Score > score = std::vector < Score > (inv.num_passages);
    int  p;
    uint32_t num_correct = 0;

    printf ("testing\n");


    // open up all the inv files
    std::vector < FILE * >fpinv = std::vector < FILE * >(inv.max_n_gram + 1);
    for (int n = inv.min_n_gram; n <= inv.max_n_gram; n++)   {
        // the inv index for this n, i.e. list of doc/count pairs for grams of this n
        char	filename[65535];
        sprintf (filename, "%s.inv-%d", inv.filename_prefix.c_str (), n);
        fpinv[n] = fopen (filename, "r");
    }


          
    auto t2 = std::chrono::high_resolution_clock::now();
    float elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
    printf ("%.2f seconds\n", elapsedSeconds);
          


    char binbuffer[65535];
    int  i, j;
    for (i = 0; i < num_tests; i++)    {
        auto start = std::chrono::high_resolution_clock::now();
      
        uint32_t	f = (random ()) % files.size ();
        const char *	filename = files[f].c_str ();
        struct stat	fstat;
        stat (filename, &fstat);
        long int	file_len = fstat.st_size;
        long int	offset = (random ()) % file_len;
        uint32_t	len = (random ())	% (inv.passage_len_bytes / 4) + (inv.passage_len_bytes / 4);
        uint32_t	start_passage_num = offset / (inv.passage_len_bytes / 2);
        if (start_passage_num > 0)	{
            start_passage_num--;
        }
        uint32_t	end_passage_num = (offset + len) / (inv.passage_len_bytes / 2);
        printf ("%d query is %s, offset=%ld [psg=%d..%d] len=%d\n",
                i, filename, offset, start_passage_num, end_passage_num, len);
        FILE *	fp = fopen (filename, "r");
        fseek (fp, offset, SEEK_SET);
        fread (binbuffer, 1, len, fp);
        // corrupt it
        for (j = 0; j < len; j++)	{
            if (pdice (prob_corrupt))	    {
                binbuffer[j] = (rand ()) % 256;
            }
        }

        auto t1 = std::chrono::high_resolution_clock::now();
	

        Passage  passage = index_passage (inv.lexicon,
                                          /* update_lexicon = */ false,
                                          inv.min_n_gram, inv.max_n_gram,
                                          binbuffer, len,
                                          /* note: we dont really care about passage ind */
                                          /* passage_ind = */ 0xdeadbeef);

        auto t2 = std::chrono::high_resolution_clock::now();
        float elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        printf ("index_passage %.2f seconds\n", elapsedSeconds);



        t1 = std::chrono::high_resolution_clock::now();
        query_with_passage (inv, fpinv, passage, scoring_params, score, min_n, max_n);
        t2 = std::chrono::high_resolution_clock::now();
        elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(t2-t1).count();
        printf ("query_with_passage %.2f seconds\n", elapsedSeconds);


        uint32_t	top_n = 5;


        bool correct = false;
        for (int j = 0; j < top_n; j++)	{
            uint32_t the_offset;
            const char *the_filename = get_passage_name(inv, score[j].ind, &the_offset);
            if (j==0) {
                if ((strcmp(the_filename, filename)==0) && (abs(the_offset - offset) < inv.passage_len_bytes) ) {
                    correct = true;
                    printf ("CORRECT\n");               
                }
                else {
                    printf ("WRONG\n");
                }
            }
            
            printf ("Result %d  score = %0.5f  passage = %d [%s-%d]\n",
                    j, score[j].val,
                    score[j].ind, 
                    the_filename, the_offset);
        }
      
#if 0
        char	passage_name[65535];
        bool	correct = false;
        uint32_t ii = 0;
        for (j = 0; j < top_n * 3; j++)	{
            const char *this_passage_name = inv.ind_to_passage_name[score[j].ind].c_str ();
            int k;
            for (k = start_passage_num; k <= end_passage_num; k++) {
                sprintf (passage_name, "%s-%d", filename, k);
                if ((strcmp (passage_name, this_passage_name)) == 0)	{
                    correct = true;
                    break;
                }
            }
            if (correct)	    {
                break;
            }
            if (j>0 && score[j].val != score[j-1].val) {
                ii ++;
            }
            if (ii == top_n) {
                break;
            }
        }
        //      printf ("Scanned top %d -- ", j);
#endif
        if (correct)	{
            //	  printf ("correct\n");
            num_correct++;
        }
        /*
          else	{
          printf ("incorrect\n");
          }
        */

        fclose (fp);


        auto end = std::chrono::high_resolution_clock::now();
        elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float>>(end-start).count();
        printf ("%.2f seconds\n", elapsedSeconds);

    }

    printf ("%.4f correct\n", ((float) num_correct) / num_tests);

    /*
      std::vector < CountPair > rs =   std::vector < CountPair > (row_sizes.size());
      i=0;
      for ( auto &kvp : row_sizes ) {
      CountPair p;
      p.passage_ind = kvp.first;
      p.count = kvp.second;
      rs[i] = p;
      i ++;
      }
      std::sort(rs.begin(), rs.end(), compare_count_pairs);
      for ( auto &c : rs ) {
      printf ("len=%d count=%d\n", c.passage_ind, c.count);
      }
    */


}

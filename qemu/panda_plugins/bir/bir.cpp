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

#include <sys/time.h>
#include <sys/resource.h>
    
#include <dlfcn.h>
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "panda_plugin.h"
    //#include "../taint/taint_ext.h"
#include "rr_log.h"
#include "panda_plugin_plugin.h"

#include "pandalog.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
    
    
bool init_plugin(void *);
void uninit_plugin(void *);

}

//#include "../taint/taint_processor.h"
#include "panda_common.h"

#include "index.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>


#ifdef CONFIG_SOFTMMU

#define UNKNOWN "unknown"

// globals
bool debug = false;
//PpScores *pps = NULL; 
IndexCommon *indc = NULL;
InvIndex *inv = NULL;
char *binary_filename = NULL;
//uint8_t *binary;
uint32_t binary_len = 0;
bool use_cache = false;
std::vector < double > scoring_params;
std::vector<FILE *>fpinv;
uint64_t first_instr=0;

// map from filename to binary contents
std::map<std::string, std::pair<uint32_t, uint8_t *>> binary;

extern uint32_t max_row_length;
extern bool bu_debug;


extern "C" {
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


double timer_stop(std::string timername) {
    if (starttime.count(timername) != 0) {
        double secs = getsecs() - starttime[timername];
        printf ("time for [%s] = %.5f\n", timername.c_str(), secs);
        return secs;
    }
    return -1.0;
}


/*
// memoized inv
// invm[n][g][p] is counts for n - gram g in passage p 
std::map < uint32_t, std::map < Gram, std:: map < uint32_t, uint32_t > > > invm;

std::map < uint32_t, uint32_t > unmarshall_row(FILE *fp, InvIndex &inv, uint32_t n, Gram g) {
    if ((invm.count(n) == 0) || (invm[n].count(g) == 0)) {
        invm[n][g] = unmarshall_doc_word_fp(fp, inv, n, g);
    }
    return invm[n][g];
}
*/


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

double *pppqs= NULL;

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

std::map < Gram, std::map < uint32_t, double > > sc;

FILE *output;
target_ulong pc_start = 0;
target_ulong pc_end = (target_ulong)~0UL;

// cache of binary -> top ranked psg 
// indexed by asid, then by pc
typedef target_ulong Asid;
typedef target_ulong Pc;
typedef uint32_t Offset;
typedef std::pair<Asid,Pc> AsidPc;
typedef std::string Filename;
typedef std::tuple<Filename,Offset,Score> PsgInfo;
std::map<AsidPc,PsgInfo> bircache;

double sec;



uint32_t run_length = 0;
uint32_t longest_run = 0;

void run_stats() {
    //    printf ("run_stats: run_length = %d\n", run_length);
    if (run_length > 40) {
        //printf ("long run: %d\n", run_length);
    }
    if (run_length > longest_run) {
        longest_run = run_length;
        if (!pandalog) 
            fprintf (output, "new longest run %d\n", longest_run);
    }
}

void bir_plog(uint32_t len, bool cached, double score, std::string filename, uint32_t offset) {
    Panda__Bir *bir = (Panda__Bir *) malloc (sizeof (Panda__Bir));
    *bir = PANDA__BIR__INIT;
    bir->len = len;
    bir->cached = cached;
    bir->highscore = score;
    if (filename == UNKNOWN) {
        bir->filename = NULL;
        bir->has_offset = false;
    }
    else {
        bir->filename = (char *) filename.c_str();
        bir->has_offset = true;
        bir->offset = offset;
    }
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.bir = bir;
    pandalog_write_entry(&ple);
    free(bir);
}


#define N 5
std::vector<Score> topN(N);

uint8_t *query_buffer = NULL;
uint8_t *query_buffer_p;
uint32_t query_len = 0;

target_ulong last_next_pc=0;

uint64_t numbb=0;


int bir_before_block_exec(CPUState *env, TranslationBlock *tb) {
    
    uint64_t instr = rr_get_guest_instr_count();    

    if (instr < first_instr) return 0;              
    if (tb->pc < pc_start || tb->pc >= pc_end) return 0;

    fprintf (output, "%u pc=0x" TARGET_FMT_lx " len=%d -- ", numbb, tb->pc, tb->size);
    

    numbb++;

    //    if (tb->size < 3) return 0;


    target_ulong asid = panda_current_asid(env);
    AsidPc asidpc = std::make_pair(asid,tb->pc);
    if (use_cache && bircache.count(asidpc) != 0) {
        // its in the cache
        auto psginfo = bircache[asidpc];
        Filename filename = std::get<0>(psginfo);
        Offset offset = std::get<1>(psginfo);
        Score score = std::get<2>(psginfo);
        if (filename == UNKNOWN) {
            run_stats();
            run_length = 0;
        }
        else {
            run_length ++;
        }
        if (pandalog) {
            //            bir_plog(tb->size, true, score, filename, offset);
        }
        else {
            //            fprintf (output, "pc=0x" TARGET_FMT_lx " len=%d  ", tb->pc, tb->size);
            fprintf (output, "birc -- sumsize=%d score=%.3f %s-%x\n", score.sumsize, score.val, (char *) filename.c_str(), offset);
        }
    }
    else {
        // not in cache
        uint8_t query_buffer[4096];
        uint32_t len = 4096;
        len = std::min((unsigned)tb->size, 4096U);
        //        if (len < 8) {
            //           fprintf (output, "2small\n");
        //        }
        //        else {
        {
            // actually copy the code into the query buffer at the correct place
            int ret = panda_virtual_memory_rw(env, tb->pc, query_buffer, indc->passage_len_bytes, 0);    
            Passage query_passage = index_passage (indc, /* update_lexicon = */ false,
                                                   query_buffer, query_len,
                                                   /* note: we dont really care about passage ind */
                                                   /* passage_ind = */ 0xdeadbeef);
            std::vector<uint32_t> best_uind;
            std::vector<Score> scores = std::vector<Score>(indc->num_uind);
            Score best_score = query_with_passage(indc, inv, fpinv, query_passage, scoring_params, scores, best_uind);
            fprintf (output, "bestscore=%f sumsize=%d -- ", best_score.val, best_score.sumsize);
            if ( (best_score.sumsize > query_len / 2) && (best_score.val < 0.2) ) {           
            
                // all the uind in scores array have highest score
                // get filename and offset for one here
                uint32_t uind = best_score.uind;               
                uint32_t psgid = *(indc->uind_to_psgs[uind].begin());
                run_length ++;
                std::pair<std::string, uint32_t> psginfo = get_passage_info(indc, psgid);
                std::string filename = psginfo.first;
                uint32_t offset = psginfo.second;
                //                fprintf (output, "bir match: file=%s offset=%d sumsize=%d val=%.4f\n",
                //                         filename.c_str(),  offset, best_score.sumsize, best_score.val);
                // let's do a little searching in the binary and see if we can get a better offset
                double max_f = 0;
                uint32_t argmax_offset;
                std::string argmax_filename;
                for (auto kvp : binary) {
                    std::string filename = kvp.first;
                    uint32_t binary_len = kvp.second.first;
                    uint8_t *bin = kvp.second.second;
                    uint32_t srch_start = std::max((int) offset - indc->passage_len_bytes, 0U);
                    uint32_t srch_end = std::min((uint32_t) offset + indc->passage_len_bytes, binary_len);                    
                    //                    printf ("filename = %s  %d %d\n", filename.c_str(), srch_start, srch_end);
                    for (uint32_t i=srch_start; i<srch_end; i++) {
                        uint32_t matches = 0;                        
                        uint32_t num_tries=0;
                        for (uint32_t j=0; j<indc->passage_len_bytes; j++) {
                            uint8_t c = query_buffer[j];
                            if (i+j >= binary_len) {
                                break;
                            }
                            matches += (c == bin[i+j]);
                            num_tries ++;
                        }                    
                        double f = ((float)matches) / num_tries;
                        if (f > max_f) {
                            max_f = f;
                            argmax_offset = i;
                            argmax_filename = filename;                           
                        }
                    }
                }
                if (max_f>0.6) {
                    fprintf (output," instr=%" PRId64 " max_f=%.4f filename=%s offset=%d\n", 
                             instr, max_f, argmax_filename.c_str(), argmax_offset);
                    offset = argmax_offset;
                }
                else {
                    fprintf (output, "search failed? %f \n ", max_f, indc->passage_len_bytes);
                }
                
                PsgInfo pi = std::make_tuple(filename, offset, best_score);
                bircache[asidpc] = pi;
            }
            else {
                // score not good enough
                fprintf(output, " score too low\n");
                run_stats();
                run_length = 0;                
                //                fprintf (output, "retreival fail\n");
                /*
                  if (pandalog) {
                  bir_plog(tb->size, false, score, UNKNOWN, 0);
                  }                       
                  else {
                  fprintf (output, "pc=0x" TARGET_FMT_lx " len=%d  ", tb->pc, tb->size);
                  fprintf (output, "bir -- %.3f unknown", score);
                  } 
                */
                Score s = {0, 0.0, 0};
                PsgInfo pi = std::make_tuple("unknown", 0xdeadbeef, s);
                bircache[asidpc] = pi;
            }
        }
            /*
        if (tb->size < 8) {
            if (!pandalog) 
                fprintf(output, "  maybe 2small");
        
        }
            */
            //if (!pandalog) fprintf(output, "\n");
        
            
        
        //        fprintf (output, "---------------------------bir end---------------------------\n\nn");
        
        
        
    }
    // if next bb to execute immediately follows this one, tb->pc == last_next_pc
    last_next_pc = tb->pc + tb->size;
    
    return 0;
}

#endif 

bool init_plugin(void *self) {    
#ifdef CONFIG_SOFTMMU
    panda_arg_list *args = panda_get_args("bir");
    if (args != NULL) {
        int i;
        std::string pfx(panda_parse_string(args, "pfx", "unk"));
        max_row_length = panda_parse_uint32(args, "max_row_length", 10000);
        pc_start = panda_parse_ulong(args, "pc_start", 0);
        pc_end = panda_parse_ulong(args, "pc_end", (target_ulong)~0UL);
        //        binary_filename = (char *) ( panda_parse_string(args, "binary", NULL));
        use_cache = panda_parse_bool(args, "use_cache");
        query_len = panda_parse_uint32(args, "query_len", 256);
        first_instr = panda_parse_uint64(args, "first_instr", 0);
        const char *file_list = panda_parse_string(args, "file_list", NULL);        
        query_buffer = (uint8_t *) malloc(query_len);
        query_buffer_p = query_buffer;
        if (file_list) {
            FILE *fp = fopen(file_list, "r");
            char *filename = NULL;
            size_t len = 0;           
            ssize_t nread;            
            while ((nread = getline(&filename, &len, fp)) != -1) {
                printf ("filename=%s\n", filename);
                filename[nread-1]=0;
                struct stat s;
                std::string fn = std::string(filename);
                stat(filename, &s);                
                printf ("reading binary [%s] %d bytes\n", filename, s.st_size);
                FILE *fp2 = fopen(filename, "r");
                uint8_t *b = (uint8_t *) malloc(s.st_size);
                std::pair<uint32_t, uint8_t *> bin = std::make_pair(s.st_size, b);
                fread(b, 1, s.st_size, fp2);
                binary[fn] = bin; 
            }
        }
        if (pandalog) {
            printf ("bir will use pandalog for output\n");
        }
        else {
            const char *output_filename = panda_parse_string(args, "output", "");
            printf("bir: writing to [%s]\n", output_filename);
            if (strlen(output_filename) == 0) {
                output = stdout;
            } else {
                output = fopen(output_filename, "w");
            }
        }
        
        if (pfx.compare("none") == 0) {
            // we just want the api -- no callbacks get registered
            printf ("bir: I am only being used for my api fns.\n");
            return true;
        }
        else {
            printf ("unmarshalling index common\n");
            indc = unmarshall_index_common(pfx, true);
            //            printf ("unmarshalling preprocessed scores\n");
            //            pps = unmarshall_preprocessed_scores(pfx,indc);                      
            printf ("unmarshalling inverted index\n");
            inv = unmarshall_invindex_min (pfx, indc);            
            // std::vector < double >
            scoring_params = std::vector < double >(indc->max_n_gram + 1);
            // weight for general_query = scoring_param[0] = 1/2
            // weight for n=1 is 1/3
            // weight for n=2 is 1/4
            // etc
            double psum = 0.0;
            double alpha = 1.0;
            for (uint32_t n = 0; n <= indc->max_n_gram; n++) {
                scoring_params[n] = pow((n + 1), alpha);
                //scoring_params[n] = 1.0 / (n + 2);
                psum += scoring_params[n];
            }
            for (uint32_t n = 0; n <= indc->max_n_gram; n++) {
                scoring_params[n] /= psum;
            }
            // open up all the inv files
            printf ("opening inv files\n");
            fpinv = std::vector < FILE * >(indc->max_n_gram + 1);
            for (uint32_t n = indc->min_n_gram; n <= indc->max_n_gram; n++)   {
                // the inv index for this n, i.e. list of doc/count pairs for grams of this n
                char filename[65535];
                snprintf (filename, 65535, "%s.inv-%d", indc->filename_prefix.c_str (), n);
                fpinv[n] = fopen (filename, "r");
            }
            
            panda_cb pcb;
            pcb.before_block_exec = bir_before_block_exec;
            panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
            return true;
        }
    }
#endif
    printf ("no pfx (inverted index file pfx) specifed \n");
    return false;
}

void uninit_plugin(void *self) {
    if (!pandalog) {
        if (output != stdout) fclose(output);
    }
}

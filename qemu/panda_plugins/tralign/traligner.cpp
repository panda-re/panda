


extern "C"{

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <assert.h>
    
}

#include "../bir/index.hpp"


using namespace std;


int main (int argc, char **argv) {
    
    if (argc != 3) {
        printf ("traligner trace_inv_index_pfx_1 trace_inv_index_pfx_2\n");
        exit (1);
    }

    char *tr1_pfx = argv[1];
    char *tr2_pfx = argv[2];
    
    printf ("tr1 is %s\n", tr1_pfx);
    printf ("tr2 is %s\n", tr2_pfx);

    Index *ind = unmarshall_index(std::string(tr1_pfx));    
    printf ("done unm\n");
    PpScores *pps = unmarshall_preprocessed_scores(std::string(tr2_pfx));

    printf ("scoring\n");
    for (uint32_t i=0; i<ind->num_passages; i++) {
        Passage passage = ind->passages[i];
        uint32_t ind;
        float score;
        query_with_passage(passage, *pps, &ind, &score);
        printf ("%d %d %.3f\n", i, ind, score);
    }
}        

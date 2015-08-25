
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

int main (int argc, char **argv) {


    if (argc != 3) {
        printf ("usage: spit_psg pfx psgid");
        exit(1);
    }
    std::string pfx = std::string(argv[1]);
    uint32_t psgid = atoi(argv[2]);

    IndexCommon *indc = unmarshall_index_common(pfx, true);
    InvIndex *inv = unmarshall_invindex_min(pfx, indc);

    uint32_t no_uind = 0xffffffff;
    uint32_t uind = no_uind;
    for (uint32_t i=0; i<indc->num_uind; i++) {
        if (indc->uind_to_psgs[i].find(psgid) != indc->uind_to_psgs[i].end()) {
            printf ("uind = %d\n", i);
            uind = i;
            break;
        }
    }
    assert (uind != no_uind);
    for (uint32_t n=indc->min_n_gram; n<=indc->max_n_gram; n++) {
        printf ("unmarshalling inv %d\n", n);
        std::string filename;
        filename =pfx + ".inv-" + std::to_string(n);
        FILE *fp = fopen((const char *) filename.c_str(), "r");
        for ( auto gram : indc->lexicon[n].grams ) {            
            inv->docs_with_word[n][gram] = unmarshall_doc_word_fp(fp, inv, n, gram);
            if (inv->docs_with_word[n][gram].count(uind) != 0) {
                // this gram is in psg
                spit_gram_hex(gram, n); printf (" ");
            }
        }
        printf ("\n");
    }
    printf ("done unmarshalling inv\n");

}

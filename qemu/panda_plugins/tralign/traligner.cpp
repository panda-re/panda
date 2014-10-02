 


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

    std::string tr1_pfx = std::string(argv[1]);
    std::string tr2_pfx = std::string(argv[2]);
    
    printf ("tr1 is %s\n", tr1_pfx.c_str());
    printf ("tr2 is %s\n", tr2_pfx.c_str());
    printf ("unmarshalling commons\n");
    IndexCommon *indc1 = unmarshall_index_common(tr1_pfx, true);
    IndexCommon *indc2 = unmarshall_index_common(tr2_pfx, true);
    printf ("unmarshalling index for tr1\n");
    Index *ind1 = unmarshall_index(tr1_pfx, indc1, true);
    printf ("unmarshalling index for tr2\n");
    Index *ind2 = unmarshall_index(tr2_pfx, indc2, true);
    indc1->num_uind = ind1->binary_to_uind.size();
    printf ("unmarshalling pp scores for tr2\n");
    PpScores *pps2 = unmarshall_preprocessed_scores(std::string(tr2_pfx));
    printf ("looking for corresponding bb in both traces\n");

    printf ("total of %d bb in tr1\n", indc1->num_passages);

    // iterate over uinque passages in trace 1
    uint32_t i=0;
    uint32_t m=0;
    uint32_t mode = 0;
    uint32_t last_p1, last_p2;
    std::set < std::pair < uint32_t, uint32_t > > edge;
    std::set < uint32_t > ps;
    for ( auto &kvp : ind1->uind_to_passage ) {
        if ((i%1000) == 0) {
            printf ("%d uinds. %d have matches\n", i, m);
        }
        uint32_t uind1 = kvp.first;
        if (indc1->uind_to_psgs[uind1].size() > 1) {
            continue;
        }
        Passage *passage1 = (Passage *) (&kvp.second);
        uint32_t uind2;
        float score;
        // find unique passage in tr2 that corresponds to passage1
        query_with_passage(indc2, passage1, pps2, &uind2, &score);
        if (score > 2.5) {
            if (indc2->uind_to_psgs[uind2].size() == 1) {
                uint32_t p1 = *(indc1->uind_to_psgs[uind1].begin());
                uint32_t p2 = *(indc2->uind_to_psgs[uind2].begin());
                std::pair <uint32_t, uint32_t> e = std::make_pair(p1, p2);
                ps.insert(p1);
                edge.insert(e);
                printf ("edge %d 1 %d 2\n", p1, p2);
            }
        }
        i ++;
    }     
    printf ("found %d singletons -- expanding\n", (int) edge.size());
    for ( auto &el : edge ) {
        for (int s=-1; s<=1; s+=2) {
            uint32_t p1 = el.first;
            uint32_t p2 = el.second;
            printf ("considering edge %d %d\n", p1, p2);
            for (uint32_t i=0; i<3; i++) {
                p1 += s;
                p2 += s;
                printf ("%d %d\n", p1, p2);
                if (ps.count(p1) != 0) {                    
                    break;
                }
                uint32_t uind1 = ind1->passages[p1];
                uint32_t uind2 = ind2->passages[p2];
                uint32_t best_uind2;
                float score;
                Passage *passage = &(ind1->uind_to_passage[uind1]);
                query_with_passage(indc2, passage, pps2, &best_uind2, &score);
                if (score > 2.5) {
                    if (best_uind2 == uind2) {
                        printf ("edge %d 1 %d 2\n", p1, p2);
                        continue;
                    }
                }
                break;
            }
        }
    }        
}

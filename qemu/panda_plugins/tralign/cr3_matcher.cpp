 


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


std::vector < uint64_t > read_cr3s(std::string tr_pfx) {
    std::vector < uint64_t > cr3s;
    std::string fn = tr_pfx + ".cr3";
    FILE *fp = fopen((char *) fn.c_str(), "r");
    uint32_t n;
    fread((void *) &n, sizeof(n), 1, fp);
    for (uint32_t i=0; i<n; i++) {
        uint64_t cr3;
        fread((void *) &cr3, sizeof(cr3), 1, fp);
        cr3s.push_back(cr3);
    }
    return cr3s;
}


bool mysf (std::pair < uint64_t, uint32_t > p1, std::pair < uint64_t, uint32_t > p2 ) {
    return (p1.second > p2.second);
}


int main (int argc, char **argv) {
    
    if (argc != 3) {
        printf ("traligner trace_inv_index_pfx_1 trace_inv_index_pfx_2\n");
        exit (1);
    }

    std::string tr1_pfx = std::string(argv[1]);
    std::string tr2_pfx = std::string(argv[2]);

    std::map < uint64_t, IndexCommon * > indc1;
    std::map < uint64_t, IndexCommon * > indc2;
    std::map < uint64_t, Index * > ind1;
    std::map < uint64_t, Index * > ind2;
    std::map < uint64_t, PpScores * > pp1;
    std::map < uint64_t, PpScores * > pp2;
    std::vector < uint64_t > tr1_cr3s = read_cr3s(tr1_pfx);
    std::vector < uint64_t > tr2_cr3s = read_cr3s(tr2_pfx);

    std::vector < std::pair < uint64_t, uint32_t > > tr1_sz;
    std::vector < std::pair < uint64_t, uint32_t > > tr2_sz;
    for ( auto cr3 : tr1_cr3s ) {
        printf ("tr1 unmarshalling cr3=0x%lx\n", cr3);
        std::string fn = tr1_pfx + "-" + std::to_string(cr3);
        indc1[cr3] = unmarshall_index_common(fn, true);
        ind1[cr3] = unmarshall_index(fn, indc1[cr3], true);
        pp1[cr3] = unmarshall_preprocessed_scores(fn);
        tr1_sz.push_back(std::make_pair(cr3, ind1[cr3]->passages.size()));
    }
    for ( auto cr3 : tr2_cr3s ) {
        printf ("tr2 unmarshalling cr3=0x%lx\n", cr3);
        std::string fn = tr2_pfx + "-" + std::to_string(cr3);
        indc2[cr3] = unmarshall_index_common(fn, true);
        ind2[cr3] = unmarshall_index(fn, indc2[cr3], true);
        pp2[cr3] = unmarshall_preprocessed_scores(fn);
        tr2_sz.push_back(std::make_pair(cr3, ind2[cr3]->passages.size()));
    }

    std::sort(tr1_sz.begin(), tr1_sz.end(), mysf);
    std::sort(tr2_sz.begin(), tr2_sz.end(), mysf);

    for ( auto &kvp1 : tr1_sz ) {
        printf ("\n");

        uint64_t cr3_1 = kvp1.first;
        uint32_t tr1_sz = kvp1.second;
        printf ("cr3=0x%lx sz=%d\n", cr3_1, kvp1.second);

        for ( auto &kvp2 : tr2_sz ) {
            uint64_t cr3_2 = kvp2.first;
            uint32_t tr2_sz = kvp2.second;
            
            float sum = 0;
            float sumsq = 0;
            // iterate over every unique psg in tr1
            // compute score for 
            for ( auto &kvp : ind1[cr3_1]->uind_to_passage ) {
                uint32_t uind2;
                float score;
                Passage *passage1 = (Passage *) (&kvp.second);
                query_with_passage(indc2[cr3_2], passage1, pp2[cr3_2], &uind2, &score);
                sum += score;
                sumsq += score * score;
            }
            uint32_t n = (ind1[cr3_1]->uind_to_passage.size());
            float avg = sum / n;
            float std = sqrt (sumsq / n - avg * avg);
            printf ("score = %.2f +/0 %.2f    (cr3_1=0x%lx, sz=%10d)   (cr3_2=0x%lx, sz=%10d)  \n", avg, std, cr3_1, tr1_sz, cr3_2, tr2_sz);
        }
    }
                    
}

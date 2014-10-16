 


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
    
    if (argc != 6) {
        printf ("traligner trace_inv_index_pfx_1 cr3_1 trace_inv_index_pfx_2 cr3_2 threshold\n");
        exit (1);
    }

    std::string tr1_pfx = std::string(argv[1]);
    uint64_t cr3_1 = strtoul(argv[2], 0, 16);
    std::string tr2_pfx = std::string(argv[3]);
    uint64_t cr3_2 = strtoul(argv[4], 0, 16);
    float threshold = atof(argv[5]);

    printf ("tr1_pfx = [%s]\n", tr1_pfx.c_str());
    printf ("tr2_pfx = [%s]\n", tr2_pfx.c_str());
    printf ("cr3_1=0x%lx cr3_2=0x%lx\n", cr3_1, cr3_2);
    printf ("threshold = %.4f\n", threshold);

    printf ("unmarshalling tr2rr for tr1\n");
    std::map < uint64_t, uint64_t > bbn1_to_tr1 = unmarshall_uint64_uint64_map(tr1_pfx + ".tr2rr");
    printf ("unmarshalling tr2rr for tr2\n");
    std::map < uint64_t, uint64_t > bbn2_to_tr2 = unmarshall_uint64_uint64_map(tr2_pfx + ".tr2rr");

    tr1_pfx = tr1_pfx + "-" + (std::to_string(cr3_1));
    tr2_pfx = tr2_pfx + "-" + (std::to_string(cr3_2));                         

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
    PpScores *pps2 = unmarshall_preprocessed_scores(tr2_pfx);
    
        
    printf ("looking for corresponding bb in both traces\n");

    printf ("total of %d bb in tr1\n", indc1->num_passages);

    // iterate over uinque passages in trace 1
    uint32_t i=0;
    uint32_t m=0;
    uint32_t mode = 0;
    uint64_t last_p1, last_p2, mp1, mp2;
    mp1=mp2=0;
    std::set < std::pair < uint64_t, uint64_t > > edge;
    std::set < uint64_t > ps1;
    std::set < uint64_t > ps2;
    std::map < uint64_t, uint64_t > match;
    for ( auto &kvp : ind1->uind_to_passage ) {
        uint32_t uind1 = kvp.first;
        Passage *passage1 = (Passage *) (&kvp.second);
        uint32_t uind2;
        float score;
        // find unique passage in tr2 that corresponds to passage1
        query_with_passage(indc2, passage1, pps2, &uind2, &score);
        if (score > 2.5) {
            match[uind1] = uind2;                
        }

        printf ("score = %.3f\n", score);

        if (indc1->uind_to_psgs[uind1].size() > 1) {
            continue;
        }

        if (score > 2.5) {
            if (indc2->uind_to_psgs[uind2].size() == 1) {
                uint64_t p1 = *(indc1->uind_to_psgs[uind1].begin());
                uint64_t p2 = *(indc2->uind_to_psgs[uind2].begin());
                std::pair <uint64_t, uint64_t> e = std::make_pair(p1, p2);
                ps1.insert(p1);
                ps2.insert(p2);
                edge.insert(e);
                printf ("singlteon match %d 1 %d 2\n", p1, p2);
            }
        }

        i ++;
    }     

    printf ("%d uniq psgs in tr 1.  %d have matches\n", ind1->uind_to_passage.size(), match.size());

    printf ("found %d singletons -- expanding\n", (int) edge.size());
    FILE *fp = fopen("passages1u2", "w");
    for (uint32_t p=0; p<indc1->num_passages; p++) {
        uint32_t uind1 = ind1->passages[p];        
        if (match.count(uind1) != 0) {
            fprintf (fp, "%d\n", match[uind1]);
        }
    }
    fclose(fp);
    fp = fopen("passages2u2", "w");
    for (uint32_t p=0; p<indc2->num_passages; p++) {
        fprintf(fp, "%d\n", ind2->passages[p]);
    }
    fclose(fp);
    
    for ( auto &el : edge ) {
        for (int s=-1; s<=1; s+=2) {
            uint64_t start1 = el.first;
            uint64_t start2 = el.second;           
            uint64_t p1 = start1;
            uint64_t p2 = start2;
            printf ("considering %d %d\n", p1, p2);
            uint64_t i = 0;
            while (true) {
                if (s == -1) {
                    assert (ind1->passages.lower_bound(p1 - 1) != ind1->passages.end());
                    assert (ind2->passages.lower_bound(p1 - 1) != ind2->passages.end());
                    p1 = ind1->passages.lower_bound(p1 - 1)->first;
                    p2 = ind1->passages.lower_bound(p2 - 1)->first;
                }
                else {
                    assert (ind1->passages.upper_bound(p1 - 1) != ind1->passages.end());
                    assert (ind2->passages.upper_bound(p1 - 1) != ind2->passages.end());
                    p1 = ind1->passages.upper_bound(p1)->first;
                    p2 = ind1->passages.upper_bound(p2)->first;
                }
                printf("p1=%d p2=%d\n", p1, p2);
                uint32_t uind1 = ind1->passages[p1];
                uint32_t uind2 = ind2->passages[p2];
                printf ("uind1=%d uind2=%d\n", uind1, uind2);
                if (match.count(uind1) == 0) {
                    // we dont have a match for this uind in trace 2
                    printf ("no match at %d\n", p1);
                    break;
                } 
                uint32_t best_uind2 = match[uind1];
                printf ("best uind2 match = %d\n", best_uind2);
                if (best_uind2 == uind2) {
                    printf ("continuing...\n");
                    // ok p1 & p2 correspond -- keep going
                    //                    printf ("adding %lu to ps\n", p1);
                    ps1.insert(p1);
                    ps2.insert(p2);
                    i++;
                    continue;                    
                }
                break;
            }
            printf ("i=%d\n", i);
            if (i>0) {
                if (p1 > indc1->num_passages) { p1 = indc1->num_passages; }
                if (p2 > indc2->num_passages) { p2 = indc2->num_passages; }
                // num of replay instructions in this extent
                uint64_t len = bbn1_to_tr1[p1] - bbn1_to_tr1[start1];
                if (p1 < start1) {
                    std::swap(p1, start1);
                    len = -len;
                }                
                assert (bbn1_to_tr1.count(start1) != 0);
                assert (bbn2_to_tr2.count(start2) != 0);
                printf ( "edge %lu,%lu,%lu,%lu,%lu\n", start1, start2, bbn1_to_tr1[start1], bbn2_to_tr2[start2], len);
            }
            printf ("%d in ps1 %d in ps2\n", ps1.size(), ps2.size());
        }
    }        

}

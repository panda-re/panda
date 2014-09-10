

extern "C" {

#include <stdio.h>
#include <assert.h>
#include "my_mem.h"

}

#include "index.hpp"


int main(int argc, char **argv) {

    if (argc != 2) {
        printf ("usage: ms pfx \n");
        exit(1);
    }

    char *pfx = argv[1];

    printf ("unmarshalling inv index\n");
    InvIndex inv = unmarshall_invindex_min(pfx);
  
    spit_inv_min(inv);

    GramPsgCounts row ;
    row.size = 0;
    row.max_size = 0;
    row.counts = NULL;

    // also spit out doc-words
    printf("Inv [\n");
    for (int n=inv.min_n_gram; n<=inv.max_n_gram; n++) {
        printf ("n=%d\n", n);
        char filename[65535];
        sprintf(filename, "%s.inv-%d", pfx, n);
        FILE *fpinv = fopen(filename, "r");   
        for ( auto &gram : inv.lexicon[n] ) {
            printf ("gram = [");
            spit_gram_hex(gram);
            printf ("]");
            unmarshall_row_fp(fpinv, inv, n, gram, row);
            printf (" len=%d\n", row.size);
            for (int i=0; i<row.size; i++) {
                uint32_t passage_ind = row.counts[i].passage_ind;
                uint32_t count = row.counts[i].count;
                printf ("(%d, %d) ", count, passage_ind);
            }
            printf ("\n");
        }
    }
  
}


#include <stdio.h>

int main (int argc, char **argv) {
    FILE *fp;

    fp=fopen(argv[1], "r");
    
    while (1) {
        int b;
        int *c = &b;
        *c=fgetc(fp);
        if (*c==EOF) break;
        if (*c=='a') {
            printf ("its an a!\n");
        }
    }
}

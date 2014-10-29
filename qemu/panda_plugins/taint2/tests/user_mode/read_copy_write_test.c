
/*
 * Simple test that reads in some data to be tainted, copies it to a new buffer,
 * and writes the new buffer to a file.
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

int main(){
    FILE *f = fopen("/dev/urandom", "r");
    char buf[100];
    fread(buf, 1, 100, f);
    fclose(f);
    char *copy = (char*)malloc(100);
    memcpy(copy, buf, 100);
    FILE *f2 = fopen("/tmp/taint_test", "w");
    fwrite(copy, 1, 100, f2);
    fclose(f2);
    free(copy);
    return 0;
}


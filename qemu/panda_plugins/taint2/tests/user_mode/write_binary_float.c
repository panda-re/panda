
#include "stdio.h"

int main(){
    float f = -12.43;
    FILE *file = fopen("binary_float.bin", "w");
    fwrite(&f, sizeof(float), 1, file);
    fclose(file);
    return 0;
}


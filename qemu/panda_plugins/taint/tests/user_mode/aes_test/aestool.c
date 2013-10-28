#include "stdio.h"
#include "stdlib.h"
#include "assert.h"
#include "aes.h"
#include "panda_mark.h"
#define SIZE 80 //Must be a multiple of 16

void main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Not enough arguments\n");
        return;
    }

    unsigned char key[] =
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    unsigned char iv[] =
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    unsigned char iv2[] =
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    unsigned char input[SIZE];
    unsigned char tmp[SIZE];
    unsigned char output[SIZE];

    //Initialize input
    int i;
    for (i = 0; i < SIZE; i++) {
        input[i] = 0;
    }

    //Initialize output
    memset(tmp, 0, sizeof(tmp));
    memset(output, 0, sizeof(output));

    //Set up AES Context
    aes_context *ctx = malloc(sizeof(aes_context));
    assert(ctx);
    aes_setkey_enc(ctx, key, 128);

    int type = atoi(argv[1]);
    switch (type) {
        int len;
        int j;
        case 0:
            label_buffer((uint64_t)&input, SIZE);
            len = SIZE / 16;
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_ENCRYPT, &(input[j*16]), &(output[j*16]));
            }
            break;
        case 1:
            len = SIZE / 16;
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_ENCRYPT, &(input[j*16]), &(tmp[j*16]));
            }
            label_buffer((uint64_t)&tmp, SIZE);
            aes_setkey_dec(ctx, key, 128);
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_DECRYPT, &(tmp[j*16]), &(output[j*16]));
            }
            break;
        case 2:
            label_buffer((uint64_t)&input, SIZE);
            aes_crypt_cbc(ctx, AES_ENCRYPT, SIZE, iv, input, output);
            break;
        case 3:
            aes_crypt_cbc(ctx, AES_ENCRYPT, SIZE, iv, input, tmp);
            label_buffer((uint64_t)&tmp, SIZE);
            aes_setkey_dec(ctx, key, 128);
            aes_crypt_cbc(ctx, AES_DECRYPT, SIZE, iv2, tmp, output);
            break;
        default:
            printf("Invalid argument\n");
            return;
    }

    if (type == 1 || type ==3) {
        int i;
        for (i = 0; i < SIZE; i++) {
            assert(input[i] == output[i]);
        }
    }

    //Query output buffer
    query_buffer((uint64_t)&output, SIZE);

    //Clean up AES
    free(ctx);
}

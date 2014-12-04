#include "stdio.h"
#include "stdlib.h"
#include "assert.h"
#include "aes.h"
#include "panda_mark.h"

unsigned char* ReadFile(char*);
unsigned long fileLen;

void main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: <input file> <encryption type>\n");
        return;
    }

    unsigned char key[] =
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    unsigned char iv[] =
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    unsigned char iv2[] =
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    unsigned char* input = ReadFile(argv[1]);
    if (input == NULL) {
        return;
    }
    unsigned char* tmp =(unsigned char*)malloc(fileLen+1);
    unsigned char* output =(unsigned char*)malloc(fileLen+1);
    if (!tmp || !output)
    {
        fprintf(stderr, "Memory error!\n");
        return;
    }

    //Set up AES Context
    aes_context *ctx = malloc(sizeof(aes_context));
    assert(ctx);
    aes_setkey_enc(ctx, key, 128);

    int type = atoi(argv[2]);
    switch (type) {
        int len;
        int j;
        case 0:
            label_buffer((uint32_t)input, fileLen);
            len = fileLen / 16;
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_ENCRYPT, &(input[j*16]), &(output[j*16]));
            }
            break;
        case 1:
            len = fileLen / 16;
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_ENCRYPT, &(input[j*16]), &(tmp[j*16]));
            }
            label_buffer((uint32_t)tmp, fileLen);
            aes_setkey_dec(ctx, key, 128);
            for (j = 0; j < len; j++) {
                aes_crypt_ecb(ctx, AES_DECRYPT, &(tmp[j*16]), &(output[j*16]));
            }
            break;
        case 2:
            label_buffer((uint32_t)input, fileLen);
            aes_crypt_cbc(ctx, AES_ENCRYPT, fileLen, iv, input, output);
            break;
        case 3:
            aes_crypt_cbc(ctx, AES_ENCRYPT, fileLen, iv, input, tmp);
            label_buffer((uint32_t)tmp, fileLen);
            aes_setkey_dec(ctx, key, 128);
            aes_crypt_cbc(ctx, AES_DECRYPT, fileLen, iv2, tmp, output);
            break;
        default:
            printf("Invalid argument\n");
            return;
    }

    if (type == 1 || type ==3) {
        int i;
        for (i = 0; i < fileLen; i++) {
            assert(input[i] == output[i]);
        }
    }

    //Query output buffer
    query_buffer((uint32_t)output, fileLen);

    //Clean up AES
    free(ctx);
    free(input);
    free(tmp);
    free(output);
}

unsigned char* ReadFile(char *name) {
    FILE *file;
    unsigned char *buffer;

    //Open file
    file = fopen(name, "rb");
    if (!file)
    {
        fprintf(stderr, "Unable to open file %s\n", name);
        return NULL;
    }

    //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    //Allocate memory
    buffer=(unsigned char *)malloc(fileLen+1);
    if (!buffer)
    {
        fprintf(stderr, "Memory error!\n");
        fclose(file);
        return NULL;
    }

    //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);
    return buffer;
}

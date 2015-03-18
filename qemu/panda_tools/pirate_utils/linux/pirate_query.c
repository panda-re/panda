
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pirate_mark.h"

void usage() {
    printf("Usage:\n");
    printf("pirate_query <file> <start_offset> <end_offset>\n");
    printf("This utility enables querying taint on bytes in <file>.\n");
    printf("\t <file> = full path to file to be labeled\n");
    printf("\t <start_offset> = beginning of region to be queried (in bytes)\n");
    printf("\t <len> = number of bytes to be queried or -1 for 'end-of-file'\n");
}

//mz match block size
#define BUFFER_SIZE 4096
char file_buffer[BUFFER_SIZE];

int main(int argc, char* argv[])
{
    char *file_name;
    long start_offset = 0;
    long region_size = 0;
    long current_offset = 0;
    FILE *hFile;
    off_t fileSize;
    struct stat stat_struct;
    int ret;
    size_t bytes_read = 0;
    size_t bytes_to_read = 0;

    if (argc != 4) {
        usage();
        exit(1);
    }

    file_name = argv[1];
    start_offset = atol(argv[2]);
    region_size = atol(argv[3]);

    hFile = fopen(file_name, "r");

    if (hFile == NULL) {
        printf("Cannot open file %s: %s\n", file_name, strerror(errno));
        exit(2);
    }

    ret = stat(file_name, &stat_struct);
    if (ret != 0){
        printf("stat() failed on %s: %s\n", file_name, strerror(errno));
        fclose(hFile);
        exit(3);
    }
    fileSize = stat_struct.st_size;

    //mz check start offset
    if (start_offset >= (long)fileSize || start_offset < 0) {
        printf("start offset invalid\n");
        fclose(hFile);
        exit(4);
    }
    //mz check region_size
    if (region_size == -1) {
        region_size = fileSize - start_offset;
    } else {
        if (start_offset + region_size >= (long)fileSize || region_size <= 0) {
            printf("region_size invalid\n");
            fclose(hFile);
            exit(4);
        }
    }

    printf("Will read %ld bytes from file\n", region_size);

    ret = fseek(hFile, start_offset, SEEK_SET);
    if (ret != 0){
        printf("fseek() failed: %s\n", strerror(errno));
        fclose(hFile);
        exit(5);
    }

    //mz we summarily assume that region_size > BUFFER_SIZE, which may not be correct
    bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
    current_offset = start_offset;

    while ( (region_size > 0) && (bytes_read = fread(&file_buffer[0], 1, bytes_to_read, hFile))) {
        vm_query_buffer(&file_buffer[0], bytes_read, /*offset=*/current_offset);
        region_size -= bytes_read;
        current_offset += bytes_read;
        //mz make sure to adjust amount to read here as well
        bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
    }

    fclose(hFile);

    printf("Completed successfully.\n");

    return 0;
}


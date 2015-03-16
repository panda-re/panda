
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
    printf("pirate_label <file> <label> <start_offset> <region_size> <chunk_size>\n");
    printf("This utility enables labeling every byte of <file> with configurable labels.\n");
    printf("\t <file> = full path to file to be labeled\n");
    printf("\t <label> = label as an int\n");
    printf("\t <start_offset> = start labeling at given offset\n");
    printf("\t <region_size> = length of region to label (-1 = whole file)\n");
    printf("\t <chunk_size> = label the file in chunks (i.e. labels are chunked for each <chunk_size> bytes)\n");
    printf("\t\t NB: chunk_size must be <= 4096 bytes (and, of course, <= <region_size>).\n");
    printf("\t\t NB: chunk_size = -1 means no splitting (single label of <label>).\n");
}

//mz match block size
#define BUFFER_SIZE 4096
char file_buffer[BUFFER_SIZE];

int main(int argc, char* argv[])
{
    char *file_name;
    long label;
    long start_offset = 0;
    long region_size = 0;
    long chunk_size = 0;
    FILE *hFile;
    off_t fileSize;
    struct stat stat_struct;
    int ret;
    size_t bytes_read = 0;
    size_t bytes_written = 0;
    size_t bytes_to_read = 0;
    int pos_label = 0;
    int single_label = 0;

    if (argc != 6) {
        usage();
        exit(1);
    }

    file_name = argv[1];
    label = atol(argv[2]);
    start_offset = atol(argv[3]);
    region_size = atol(argv[4]);
    chunk_size = atol(argv[5]);

    hFile = fopen(file_name, "r+");

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

    ret = fseek(hFile, start_offset, SEEK_SET);
    if (ret != 0){
        printf("fseek() failed: %s\n", strerror(errno));
        fclose(hFile);
        exit(5);
    }

    //mz max possible
    bytes_to_read = BUFFER_SIZE;

    if (chunk_size == -1) {
        single_label = 1;
    } 
    else if (chunk_size == 1) {
        pos_label = 1;
    }
    else {
        if (chunk_size <= 0 || chunk_size > region_size || chunk_size > BUFFER_SIZE) {
            printf("chunk_size invalid\n");
            fclose(hFile);
            exit(5);
        }
        bytes_to_read = chunk_size;
    }

    //mz if single_label or pos_label, make sure we don't over-read
    bytes_to_read = (region_size < bytes_to_read) ? region_size : bytes_to_read;

    while ( (region_size > 0) && (bytes_read = fread(&file_buffer[0], 1, bytes_to_read, hFile)) ) {
        //identity(&file_buffer[0], bytes_read);
        if (pos_label) {
            vm_label_buffer_pos(&file_buffer[0], bytes_read, start_offset);
        }
        else if (single_label) {
            vm_label_buffer(&file_buffer[0], label, bytes_read); 
        }
        else {
            // Else, chunk label.  Label the chunk with the starting offset of
            // the chunk
            vm_label_buffer(&file_buffer[0], start_offset, bytes_read);
        }

        ret = fseek(hFile, (0 - bytes_read), SEEK_CUR);
        if (ret != 0){
            printf("fseek() failed: %s\n", strerror(errno));
            fclose(hFile);
            exit(6);
        }

        bytes_written = fwrite(&file_buffer[0], 1, bytes_read, hFile);
        if (bytes_written != bytes_read) {
            printf("Write failed: %s\n", strerror(errno));
            fclose(hFile);
            exit(7);
        }

        start_offset += bytes_read;
        region_size -= bytes_read;

        //mz make sure to adjust amount to read here as well
        if (pos_label || single_label) {
            bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
        }
        else {
            bytes_to_read = (region_size > chunk_size) ? chunk_size : region_size;
        }
    }

    fclose(hFile);

    vm_guest_util_done();

    printf("Completed successfully\n");

    return 0;
}


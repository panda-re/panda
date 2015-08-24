//


extern "C"{

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
    
}

#include "index.hpp"
#include<map>


using namespace std;



uint32_t index_file_aux(char *filename, 
                        long start_offset,
                        uint32_t passage_num,
                        IndexCommon *indc,
                        Index *index,
                        uint32_t passage_length,
                        uint32_t file_length) {
    static uint8_t *binary = NULL;
    if (binary == NULL) {
        binary = (uint8_t *) malloc(passage_length);
    }
    char *p = filename;
    while (*p != '\0') {
        if (*p == '\n') {
            *p = 0;
            break;
        }
        p ++;
    }
    FILE *fp = fopen(filename, "r");
    fseek(fp, start_offset, SEEK_SET);
    uint32_t n;
    long pos = start_offset;
    bool special = false;
    while (n = fread(binary, 1, passage_length, fp)) {
        if (n == 0) {
            // done
            break;
        }
        if (n < passage_length) {
            // this is the special last, short passage
            if (special) {
                // only create this special once
                break;
            }
            special = true;
            // last passage is last n bytes
            fseek(fp, file_length - passage_length, SEEK_SET);
            pos = file_length - passage_length;
            n = fread(binary, 1, passage_length, fp);
        }    
        if (n > 0) {
            //      printf ("\npos=%d\n", pos);
            index_this_passage(indc, index, binary, n, passage_num);
            passage_num += 2;
        }
        pos += n;
    }
    fclose(fp);
    printf("%d passages\n", indc->num_passages);
    return passage_num;
}



uint32_t passage_num = 0;

void index_file(IndexCommon *indc, Index *index, char *filename, uint32_t passage_length, uint32_t file_length, uint32_t step) {
    static uint8_t *file_buf = NULL;
    static uint32_t file_buf_len = 0;

    struct stat s;
    int ret = stat(filename, &s);
    assert (ret == 0);
    if (file_buf_len < s.st_size) {
        file_buf_len = s.st_size;
        if (file_buf == NULL) {
            file_buf = (uint8_t *) malloc(s.st_size);
        }
        else {
            file_buf = (uint8_t *) realloc(file_buf, s.st_size);
        }
    }
    FILE *fp = fopen(filename, "r");
    ret = fread(file_buf, 1,  s.st_size, fp);
    assert (ret == s.st_size);
    for (uint32_t i=0; i<s.st_size-passage_length; i+=step ) {
        index_this_passage(indc, index, file_buf+i, passage_length, passage_num);
        passage_num+=step;
    }

    /*     
    char *buf 
    uint32_t first_passage_num = indc->num_passages;
    // index passages starting from offset 0
    index_file_aux(filename, 0, first_passage_num, indc, index, passage_length, file_length);
    // index passages starting from offset passge_length/2 
    index_file_aux(filename, passage_length/2, first_passage_num+1, indc, index, passage_length, file_length);
    */
}






int main (int argc, char **argv) {
    if (argc != 7 ) {
        printf ("usage: bi file_list_file filename_pfx min_n max_n passage_len step\n");
        exit(1);
    }
    struct stat fs;
    char *file_list_file = argv[1];
    std::string filename_prefix = std::string(argv[2]);
    uint32_t min_n_gram = atoi(argv[3]);
    uint32_t max_n_gram = atoi(argv[4]);
    uint32_t passage_len = atoi(argv[5]);
    uint32_t step = atoi(argv[6]);
    assert (min_n_gram <= max_n_gram);
    IndexCommon *indc = new_index_common(filename_prefix, min_n_gram, max_n_gram, passage_len);  
    Index *index = new Index;
    uint32_t num_files = 0;
    uint64_t total_bytes = 0;
    FILE *fp = fopen(file_list_file, "r");
    while (1) {
        size_t n = 0;
        char *filename = NULL;
        int x = getline(&filename, &n, fp);
        if (x==-1) {
            break;
        }
        filename[strlen(filename)-1] = 0;
        stat(filename, &fs);   
        printf ("%d indexing file %s len=%d\n", num_files, filename, fs.st_size);
        indc->filename_to_first_passage[filename] = indc->num_passages;
        indc->first_passage_to_filename[indc->num_passages] = filename;
        index_file(indc, index, filename, passage_len, fs.st_size, step);    
        //    spit_index(index);
        total_bytes += fs.st_size;
        num_files++;
    }
    printf ("%d passages in total\n", indc->num_passages);
    marshall_index_common(indc);
    InvIndex *inv = invert(indc, index);
    printf ("marshalling inv index\n");  
    indc->filename_prefix = filename_prefix;
    marshall_invindex(indc, inv);
    printf ("total_bytes = %ld\n", total_bytes);
    printf ("indexing complete\n");
    
}


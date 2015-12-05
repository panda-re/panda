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




uint32_t passage_num = 0;

// count grams in this file and add to index
void index_file(IndexCommon *indc, Index *index, char *filename, uint32_t passage_length, uint32_t file_length, uint32_t step) {
    static uint8_t *file_buf = NULL;
    static uint32_t file_buf_len = 0;

    if (file_buf_len < file_length) {
        file_buf_len = file_length;
        if (file_buf == NULL) {
            file_buf = (uint8_t *) malloc(file_length);
        }
        else {
            file_buf = (uint8_t *) realloc(file_buf, file_length);
        }
    }
    FILE *fp = fopen(filename, "r");
    int ret = fread(file_buf, 1,  file_length, fp);
    assert (ret == file_length);
    for (uint32_t i=0; i<file_length-passage_length; i+=step ) {
        // passage number is offset within file
        index_this_passage(indc, index, file_buf+i, passage_length, passage_num);
        passage_num++;
    }

}






int main (int argc, char **argv) {
    if (argc != 8 ) {
        printf ("usage: bi file_list_file filename_pfx min_n max_n passage_len step ind\n");
        printf ("where ...\n  file_list_file is the name of a file where each line is the name of a file to be indexed.\n");
        printf ("  filename_pfx is full path pfx for index and inv index files to be created\n");
        printf ("  min_n, max_n are ngram limits\n");
        printf ("  passage_len is how many bytes in an indexed passage\n");
        printf ("  step is how many bytes to step between passages\n");
        printf ("  ind is 1 to marshall index in addition to inverted index\n");
        exit(1);
    }
    struct stat fs;
    char *file_list_file = argv[1];
    std::string filename_prefix = std::string(argv[2]);
    uint32_t min_n_gram = atoi(argv[3]);
    uint32_t max_n_gram = atoi(argv[4]);
    uint32_t passage_len = atoi(argv[5]);
    uint32_t step = atoi(argv[6]);
    int marshall_ind = atoi(argv[7]);
    printf ("file_list_file = %s\n", file_list_file);
    printf ("pfx = %s\n", filename_prefix.c_str());
    printf ("grams = %d .. %d\n", min_n_gram, max_n_gram);
    printf ("passage_len = %d\n", passage_len);
    printf ("step = %d\n", step);
    printf ("marshall_ind = %d\n", marshall_ind);
    
    assert (min_n_gram <= max_n_gram);
    IndexCommon *indc = new_index_common(filename_prefix, min_n_gram, max_n_gram, passage_len, step);  
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
        printf ("%d indexing file %s len=%d start_psg=%d\n", num_files, filename, fs.st_size, indc->num_passages);
        indc->filename_to_first_passage[filename] = indc->num_passages;
        indc->first_passage_to_filename[indc->num_passages] = filename;
        index_file(indc, index, filename, passage_len, fs.st_size, step);    
        //    spit_index(index);
        total_bytes += fs.st_size;
        num_files++;
    }
    printf ("%d passages in total\n", indc->num_passages);
    marshall_index_common(indc);
    if (marshall_ind == 1) {
        marshall_index(indc, index);
    }
    InvIndex *inv = invert(indc, index);
    printf ("marshalling inv index\n");  
    indc->filename_prefix = filename_prefix;
    marshall_invindex(indc, inv);
    printf ("total_bytes = %ld\n", total_bytes);
    printf ("indexing complete\n");
    
}


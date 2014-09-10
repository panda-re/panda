//


extern "C"{

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <assert.h>

}

#include "index.hpp"
#include<map>


using namespace std;

/////////////////////////////////////////
// Indexer

Indexer new_indexer(uint32_t min_n_gram, uint32_t max_n_gram,
		    uint32_t passage_len_bytes) {
  Indexer indexer = Indexer();
  indexer.min_n_gram = min_n_gram;
  indexer.max_n_gram = max_n_gram;
  indexer.passage_len_bytes;
  indexer.index = new_index(min_n_gram, max_n_gram, passage_len_bytes);
  return indexer;
}
  
 

/*
  Count n-grams for this binary blob (a passage).
  The lexicon and index that come, packed into indexer,
  both get updated.
*/
void index_this_passage(Indexer &indexer, char *binary_passage, uint32_t len, uint32_t passage_ind) {    
  Index &index = indexer.index;
  Passage passage = 
    index_passage(index.lexicon, 
		  true, 
		  indexer.min_n_gram, indexer.max_n_gram,
		  binary_passage, len,
		  passage_ind);
  //  spit_passage(passage);
  index.num_passages ++;
  index.passages[passage_ind] = passage;
  assert (passage.ind == passage_ind);
  //  printf ("passage_ind=%d  passage.ind=%d\n", passage_ind, passage.ind);

}


uint32_t index_file_aux(char *filename, 
                        long start_offset,
                        uint32_t passage_num,
                        Indexer &indexer,
                        uint32_t passage_length,
			uint32_t file_length) {
  static char *binary = NULL;
  if (binary == NULL) {
    binary = (char *) malloc(passage_length);
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
        index_this_passage(indexer, binary, n, passage_num);
      passage_num += 2;
    }
    pos += n;
  }
  fclose(fp);
  return passage_num;
}




void index_file(Indexer &indexer, char *filename, uint32_t passage_length, uint32_t file_length) {
  uint32_t first_passage_num = indexer.index.num_passages;
  // index passages starting from offset 0 in file
  index_file_aux(filename, 0, first_passage_num, indexer, passage_length, file_length);
  // index passages starting from offset passge_length/2 
  index_file_aux(filename, passage_length/2, first_passage_num+1, indexer, passage_length, file_length);
}



InvIndex invert(Index &index) {
  int i;
  printf ("Inverting index\n");
  InvIndex inv = InvIndex();
  uint32_t min_n = index.min_n_gram;
  uint32_t max_n = index.max_n_gram;
  inv.min_n_gram = min_n;
  inv.max_n_gram = max_n;
  inv.passage_len_bytes = index.passage_len_bytes;
  inv.lexicon = index.lexicon;
  inv.filename_to_first_passage = index.filename_to_first_passage;
  inv.first_passage_to_filename = index.first_passage_to_filename;
  //  inv.total_count.resize(max_n+1);
  //  inv.general_query.resize(max_n+1);
  // iterate over passages in the index
  uint32_t ii=0;
  uint32_t i100 = index.num_passages / 100;
  for ( auto &kvp : index.passages ) {
      if ((ii % i100) == 0) {
          printf ("%d %d \n", ii/i100, ii);
      }
      ii ++;

    uint32_t passage_ind = kvp.first;
    Passage passage = kvp.second;
    assert (passage_ind == passage.ind);
    // iterate over distributions in this passage
    for ( auto &kvp : passage.contents ) {
      uint32_t n = kvp.first;
      PassageDist pd = kvp.second;
      assert (pd.n == n);
      // iterate over gram counts in this distribution
      for ( auto &kvp : pd.count ) {
	Gram gram = kvp.first;
	uint32_t count = kvp.second;
    inv.docs_with_word[pd.n][gram][passage.ind]++;
	inv.general_query[pd.n][gram] ++;
	inv.total_count[pd.n] += count;
	assert (inv.docs_with_word[pd.n][gram].size() != 0);
      }
    }
  }
  // create map from index back to passage name (a string)
  // and populate passage lengths in inv index
  inv.num_passages = index.num_passages;
  // NB: inv.filename_prefix unspecified at this time
  // NB: inv.map_dw doesnt exist yet. 
  // this is generated when we write out the file
  return inv;
}     




int main (int argc, char **argv) {
  if (argc != 6) {
    printf ("usage: mi file_list_file filename_pfx min_n max_n passage_len\n");
    exit(1);
  }
  struct stat fs;
  char *file_list_file = argv[1];
  std::string filename_prefix = std::string(argv[2]);
  uint32_t min_n_gram = atoi(argv[3]);
  uint32_t max_n_gram = atoi(argv[4]);
  uint32_t passage_len = atoi(argv[5]);
  assert (min_n_gram <= max_n_gram);
  Indexer indexer = new_indexer(min_n_gram, max_n_gram, passage_len);  
  Index &index = indexer.index;
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
    index.filename_to_first_passage[filename] = index.num_passages;
    index.first_passage_to_filename[index.num_passages] = filename;
    index_file(indexer, filename, passage_len, fs.st_size);    
    //    spit_index(index);
    total_bytes += fs.st_size;
    num_files++;
  }
  printf ("%d passages in total\n", index.num_passages);

  //  printf ("after indexing.\n");
  //  spit_index(indexer.index);
  

  //  spit_index(index);
  // NB: We dont really want to marshall the index
  //  printf ("marshalling index to %s\n", filename_prefix);
  //  marshall_index(filename_prefix, index);
  InvIndex inv = invert(index);



  //  spit_inv(inv);
  printf ("marshalling inv index\n");  
  inv.filename_prefix = filename_prefix;
  marshall_invindex(inv);
  printf ("total_bytes = %ld\n", total_bytes);
  printf ("indexing complete\n");
}


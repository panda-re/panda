/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "my_mem.h"

const char *pool_names[] = {
  "poolid_iferret_log",
  "poolid_codeblock_int_hashtable",
  "poolid_int64_int64_hashtable",
  "poolid_int_IferretCodeBlock_hashtable",
  "poolid_int_int_hashtable",
  "poolid_uint32_uint32_hashtable",
  "poolid_int_string_hashtable",
  "poolid_pidpc_codeblock_hashtable",
  "poolid_string_int64_hashtable",
  "poolid_string_int_hashtable",
  "poolid_iferret_codeblock",
  "poolid_iferret_pidpc",
  "poolid_int_set",
  "poolid_iferret_shadow",
  "poolid_ind_to_label_map",
  "poolid_bitset",
  "poolid_sparsebitset",
  "poolid_label_set",
  "poolid_gr_int_arr",
  "poolid_gr_label_arr",
  "poolid_gr_str_arr",
  "poolid_iferret_breakpoints",
  "poolid_iferret_collect_blocks",
  "poolid_monitor",
  "poolid_asciihex",
  "poolid_translate",
  "poolid_syscall",
  "poolid_syscall_stack",
  "poolid_timer",
  "poolid_packet_buffer",
  "poolid_iferret",
  "poolid_shad_dir", 
  "poolid_iferret_dist",
  "poolid_string_dist_hashtable",
  "poolid_uint32_dist_hashtable",
  "poolid_uint64_uint32_hashtable",
  "poolid_iferret_bb",
  "poolid_uint32_bb_hashtable",
  "poolid_iferret_thread",
  "poolid_iferret_trace",
  "poolid_thread_trace_hashtable",
  "poolid_taint_processor",
  "poolid_dynamic_log",
  "poolid_last"
};

typedef struct {
  uint64_t bytes_alloc;
  uint64_t num_malloc;
  uint64_t num_free;
  uint64_t num_strdup;
} pool_info;

pool_info mem_usage[poolid_last];


void spit_mem_usage(void) {
   int i;
   for (i = 0; i < poolid_last; i++) {
       printf("%s: ", pool_names[i]);
       printf("bytes = %llu, num_malloc=%llu, num_free=%llu, num_strdup=%llu\n",
	      (long long unsigned int) mem_usage[i].bytes_alloc, 
	      (long long unsigned int) mem_usage[i].num_malloc,
	      (long long unsigned int) mem_usage[i].num_free,
	      (long long unsigned int) mem_usage[i].num_strdup);
   }
}


void *my_malloc(size_t n, pool_id pid) {
  static uint64_t my_malloc_counter = 0;
    void *p = malloc(n);
    assert(p != NULL);
    assert(pid < poolid_last && pid >= 0);
    mem_usage[pid].bytes_alloc += n; 
    mem_usage[pid].num_malloc++;
    my_malloc_counter++;
    /*    
    if ((my_malloc_counter % 1000) == 0) {
      spit_mem_usage();
    }
    */
    return p;
}

void *my_calloc(size_t nmem, size_t memsz, pool_id pid) {
    void *p = calloc(nmem, memsz);
    assert(p != NULL);
    assert(pid < poolid_last && pid >= 0);
    mem_usage[pid].bytes_alloc += (nmem * memsz); 
    mem_usage[pid].num_malloc++;
    return p;
}

void *my_realloc(void *p, size_t n, size_t old_n, pool_id pid) {
    void *q = realloc(p, n);
    assert(q != NULL);
    assert(pid < poolid_last && pid >= 0);
    if (n > old_n) {
    	mem_usage[pid].bytes_alloc += (n - old_n); 
    	mem_usage[pid].num_malloc++;
    }
    else {
    	mem_usage[pid].bytes_alloc -= (old_n - n); 
	mem_usage[pid].num_free++;
    }
    return q;
}

void my_free(void *p, size_t n, pool_id pid) {
    if (p) {
       free(p);
       assert(pid < poolid_last && pid >= 0);
       mem_usage[pid].bytes_alloc -= n; 
       mem_usage[pid].num_free++;
    }
}

char * my_strdup(const char *p, pool_id pid) {
    char *q = strdup(p);
    assert(q != NULL);
    assert(pid < poolid_last && pid >= 0);
    mem_usage[pid].bytes_alloc += (strlen(p) + 1); 
    mem_usage[pid].num_strdup++;
    return q;
}


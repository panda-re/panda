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

#ifndef __MY_MEM_H_
#define __MY_MEM_H_

#include <stdlib.h>
#include <assert.h>
#include <string.h>

typedef enum {
  poolid_iferret_log = 0,
  poolid_codeblock_int_hashtable,
  poolid_int64_int64_hashtable,
  poolid_int_IferretCodeBlock_hashtable,
  poolid_int_int_hashtable,
  poolid_uint32_uint32_hashtable,
  poolid_int_string_hashtable,
  poolid_pidpc_codeblock_hashtable,
  poolid_string_int64_hashtable,
  poolid_string_int_hashtable,
  poolid_iferret_codeblock,
  poolid_iferret_pidpc,
  poolid_int_set,
  poolid_iferret_shadow,
  poolid_ind_to_label_map,
  poolid_bitset,
  poolid_sparsebitset,
  poolid_label_set,
  poolid_gr_int_arr,
  poolid_gr_label_arr,
  poolid_gr_str_arr,
  poolid_iferret_breakpoints,
  poolid_iferret_collect_blocks,
  poolid_monitor,
  poolid_asciihex,
  poolid_translate,
  poolid_syscall,
  poolid_syscall_stack,
  poolid_timer,
  poolid_packet_buffer,
  poolid_iferret,
  poolid_shad_dir,
  poolid_iferret_dist,
  poolid_string_dist_hashtable,
  poolid_uint32_dist_hashtable,
  poolid_uint64_uint32_hashtable,
  poolid_iferret_bb,
  poolid_uint32_bb_hashtable,
  poolid_iferret_thread,
  poolid_iferret_trace,
  poolid_thread_trace_hashtable,
  poolid_taint_processor,
  poolid_dynamic_log,
  poolid_last
} pool_id;


void spit_mem_usage(void);

void *my_malloc(size_t n, pool_id pid);
void *my_calloc(size_t nmemb, size_t memsz, pool_id pid);
void *my_realloc(void *p, size_t n, size_t old_n, pool_id pid);
void my_free(void *p, size_t n, pool_id pid);
char * my_strdup(const char *p, pool_id pid);


#endif

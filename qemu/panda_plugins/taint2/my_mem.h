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
#ifdef __cplusplus
#include <memory>
#endif

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


#ifdef __cplusplus
extern "C" {
#endif
void spit_mem_usage(void);

void *my_malloc(size_t n, pool_id pid);
void *my_calloc(size_t nmemb, size_t memsz, pool_id pid);
void *my_realloc(void *p, size_t n, size_t old_n, pool_id pid);
void my_free(void *p, size_t n, pool_id pid);
char * my_strdup(const char *p, pool_id pid);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
enum class Memevent {
    ALLOC,
    FREE,
    CTOR,
    DTOR
};

void my_mem_log(Memevent event, size_t amount, pool_id pid);

/* C++ STL allocator that uses our heap-tracking code */
template <typename T, pool_id poolid>
class mymem_allocator : public std::allocator<T> {
 public:
    //Returns the address of r as a pointer type. This function and the following function are used to convert references to pointers.
    //T* address(T& r) const;
    typedef T* pointer;
    typedef T  value_type;
    typedef const T& const_reference;
    typedef const T* const_pointer;
    typedef T& reference;
    //Returns the address of r as a const_pointer type.
    //const T* address(const T& r) const;

    //Allocates storage for n values of T. Uses the value of hint to optimize storage placement, if possible.
    pointer allocate(size_t n, const void* hint=0){
        pointer tmp = std::allocator<mymem_allocator<T, poolid>::value_type>::allocate(n, hint);
        if(nullptr != tmp) my_mem_log(Memevent::ALLOC, n * sizeof(T), poolid);
        return tmp;
    }

    //Deallocates storage obtained by a call to allocate.
    void deallocate(pointer p, size_t n){
        my_mem_log(Memevent::FREE, n, poolid);
        std::allocator<mymem_allocator<T, poolid>::value_type>::deallocate(p,n * sizeof(T));
    }

    //Returns the largest possible storage available through a call to allocate.
    //size_t max_size();

    //Constructs an object of type T at the location of p, using the value of val in the call to the constructor for T.
    void construct(pointer p, const_reference val){
        my_mem_log(Memevent::CTOR, 0, poolid);
        std::allocator<mymem_allocator<T, poolid>::value_type>::construct(p,val);
    }

    // destroy p
    void destroy(pointer p){
        my_mem_log(Memevent::DTOR, 0, poolid);
        std::allocator<mymem_allocator<T, poolid>::value_type>::destroy(p);
    }

    // provides ability to allocate for types other than T
    template<typename _Tp1>
    struct rebind
    {
        typedef mymem_allocator<_Tp1, poolid> other;
    };
};
#endif // __cplusplus
#endif

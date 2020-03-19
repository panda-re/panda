// Macros to help with cb-support.c

// The COMBINE_TYPES series of macros will combine a list of
// (type1, var1, type2, var2, ...) into (type1 var1, type2 var2...)
// Supports up to 10 elements (5 pairs)
// Given a list of types and variables, combine them - (int, b, bool, d) -> (int b, bool d)
#define COMBINE_TYPES0(...)
#define COMBINE_TYPES1_(second, ...) second
#define COMBINE_TYPES1(first, ...) first COMBINE_TYPES1_(__VA_ARGS__)
#define COMBINE_TYPES2_(second, ...) second, COMBINE_TYPES1(__VA_ARGS__)
#define COMBINE_TYPES2(first, ...) first COMBINE_TYPES2_(__VA_ARGS__)
#define COMBINE_TYPES3_(second, ...) second, COMBINE_TYPES2(__VA_ARGS__)
#define COMBINE_TYPES3(first, ...) first COMBINE_TYPES3_(__VA_ARGS__)
#define COMBINE_TYPES4_(second, ...) second, COMBINE_TYPES3(__VA_ARGS__)
#define COMBINE_TYPES4(first, ...) first COMBINE_TYPES4_(__VA_ARGS__)
#define COMBINE_TYPES5_(second, ...) second, COMBINE_TYPES4(__VA_ARGS__)
#define COMBINE_TYPES5(first, ...) first COMBINE_TYPES5_(__VA_ARGS__)

// Edge case: when we get a single argument we want fn(void) which is called as fn()
#define COMBINE_TYPES_void(...) void
#define COUNT_PAIRS_COMBINE(_1,__1,_2,__2,_3,__3,_4,__4,_5,__5,num,...) COMBINE_TYPES ## num
#define COMBINE_TYPES(...) COUNT_PAIRS_COMBINE(__VA_ARGS__,5,ERROR,4,ERROR,3,ERROR,2,ERROR,1,void)(__VA_ARGS__)

// The EVERY_SECOND series of macros will subselect from a list of
// (type1, var1, type2, var2, ...) into (var1, var2, ...)
// Supports up to 10 elements (5 pairs)
// Inspired by https://stackoverflow.com/a/45758785
#define EVERY_SECOND0(...)
#define EVERY_SECOND1_(second, ...) second 
#define EVERY_SECOND1(first, ...) EVERY_SECOND1_(__VA_ARGS__)
#define EVERY_SECOND2_(second, ...) second, EVERY_SECOND1(__VA_ARGS__)
#define EVERY_SECOND2(first, ...) EVERY_SECOND2_(__VA_ARGS__)
#define EVERY_SECOND3_(second, ...) second, EVERY_SECOND2(__VA_ARGS__)
#define EVERY_SECOND3(first, ...) EVERY_SECOND3_(__VA_ARGS__)
#define EVERY_SECOND4_(second, ...) second, EVERY_SECOND3(__VA_ARGS__)
#define EVERY_SECOND4(first, ...) EVERY_SECOND4_(__VA_ARGS__)
#define EVERY_SECOND5_(second, ...) second, EVERY_SECOND4(__VA_ARGS__)
#define EVERY_SECOND5(first, ...) EVERY_SECOND5_(__VA_ARGS__)
#define COUNT_PAIRS_SECOND(_1,__1,_2,__2,_3,__3,_4,__4,_5,__5,num,...) EVERY_SECOND ## num
#define EVERY_SECOND(...) COUNT_PAIRS_SECOND(__VA_ARGS__,5,5,4,4,3,3,2,2,1,0)(__VA_ARGS__)

#define ENTRY_NAME(name, ...) \
         name (__VA_ARGS__)

#define ENTRY_NAME0(name) \
         name ()

// TODO: These require name and name_upper so we can both use entry.name(...) and
//       panda_cbs[NAME]. Unfortunatley the preprocessor can't do the case conversion
//       for us. Is there a better way?

// Normal callbacks. if enabled, call the function. No return values
#define MAKE_VOID_CALLBACK(name_upper, name, ...) \
    void panda_callbacks_ ## name(COMBINE_TYPES(__VA_ARGS__)) { \
        panda_cb_list *plist; \
        for (plist = panda_cbs[PANDA_CB_ ## name_upper]; \
             plist != NULL; \
             plist = panda_cb_list_next(plist)) { \
              if (plist->enabled) \
                plist->entry. ENTRY_NAME(name, EVERY_SECOND(__VA_ARGS__)); \
        } \
    }

// Normal callback. If enabled, call the function. OR all results together
// and return true if any called function returns true
#define MAKE_BOOL_CALLBACK(name_upper, name, ...) \
    bool panda_callbacks_ ## name(COMBINE_TYPES(__VA_ARGS__)) { \
        panda_cb_list *plist; \
        bool any_true = false; \
        for (plist = panda_cbs[PANDA_CB_ ## name_upper]; \
             plist != NULL; \
             plist = panda_cb_list_next(plist)) { \
              if (plist->enabled) \
                any_true |= plist->entry. ENTRY_NAME(name, EVERY_SECOND(__VA_ARGS__)); \
        } \
        return any_true; \
    }

// Callback only to be checked if in replay. These are all void because they can't change execution
#define MAKE_REPLAY_ONLY_CALLBACK(name_upper, name, ...) \
    void panda_callbacks_ ## name(COMBINE_TYPES(__VA_ARGS__)) { \
        if (rr_in_replay()) { \
          panda_cb_list *plist; \
          for (plist = panda_cbs[PANDA_CB_ ## name_upper]; \
               plist != NULL; \
               plist = panda_cb_list_next(plist)) { \
                if (plist->enabled) \
                  plist->entry. ENTRY_NAME(name, EVERY_SECOND(__VA_ARGS__)); \
          } \
        } \
    }


#if 0
// Coming soon
// Memory-callbacks call both virt_mem_xyz then phys_mem_xyz
#define MAKE_VOID_MEM_CALLBACK(name_upper, name, ...) \
    void panda_callbacks_ ## name(COMBINE_TYPES(__VA_ARGS__)) { \
        panda_cb_list *plist; \
        for (plist = panda_cbs[PANDA_CB_ ## name_upper]; \
             plist != NULL; \
             plist = panda_cb_list_next(plist)) { \
              if (plist->enabled) \
                plist->entry. MEM_ENTRY_NAME(virt, name, EVERY_SECOND(__VA_ARGS__)); \
        } \
        if (panda_cbs[PANDA_CB_PHYS_ ## name_upper]) { \
          hwaddr paddr = get_paddr(env, addr, ram_ptr); \
          for(plist = panda_cbs[PANDA_CB_PHYS_ ## name_upper]; plist != NULL;
              plist = panda_cb_list_next(plist)) {
              if (plist->enabled) plist->entry.phys_mem_before_read(env, env->panda_guest_pc,
                                                                    paddr, data_size);
          }

        } \
    }

#endif

#ifndef PROC_START_LINUX_H
#define PROC_START_LINUX_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

#define MAX_PATH_LEN 256
#define MAX_NUM_ARGS 10
#define MAX_NUM_ENV 20

// https://lwn.net/Articles/519085/
struct auxv_values {
    int argc;
    target_ulong argv_ptr_ptr;             // guest pointer to const char* argv[]
    target_ulong arg_ptr[MAX_NUM_ARGS];    // contains guest pointers from from argv[]
    char argv[MAX_NUM_ARGS][MAX_PATH_LEN]; // contains host strings from argv[]
    int envc;
    target_ulong env_ptr_ptr;              // guest pointer to const char* envp[]
    target_ulong env_ptr[MAX_NUM_ENV];     // contains guest pointers from env[]
    char envp[MAX_NUM_ENV][MAX_PATH_LEN];  // contains host strings for envp[]
    target_ulong execfn_ptr;               // contains guest pointer to exec function
    char execfn[MAX_PATH_LEN];              
    target_ulong phdr;
    target_ulong entry;
    target_ulong ehdr;
    target_ulong hwcap;
    target_ulong hwcap2;
    target_ulong pagesz;
    target_ulong clktck;
    target_ulong phent;
    target_ulong phnum;
    target_ulong base;
    target_ulong flags;
    target_ulong uid;
    target_ulong euid;
    target_ulong gid;
    target_ulong egid;
    bool secure;
    target_ulong random;
    target_ulong platform;
    target_ulong program_header; // this is just PHDR - sizeof(ehdr). it's a best guess
};

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif

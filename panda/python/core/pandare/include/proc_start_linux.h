
#define MAX_PATH_LEN 256

struct auxv_values {
    char procname[MAX_PATH_LEN];
    target_ulong phdr;
    target_ulong entry;
    target_ulong ehdr;
    target_ulong hwcap;
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
};


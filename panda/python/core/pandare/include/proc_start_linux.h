
#define MAX_PATH_LEN 256

struct auxv_values {
    char procname[MAX_PATH_LEN];
    target_ulong phdr;
    target_ulong entry;
};


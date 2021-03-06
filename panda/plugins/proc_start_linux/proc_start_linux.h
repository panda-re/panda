#ifndef PROC_START_LINUX_H
#define PROC_START_LINUX_H

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

#define MAX_PATH_LEN 256

struct auxv_values {
    char procname[MAX_PATH_LEN];
    target_ulong phdr;
    target_ulong entry;
};

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif
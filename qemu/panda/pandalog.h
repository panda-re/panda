
#ifndef __PANDALOG_H_
#define __PANDALOG_H_

#include "pandalog.pb-c.h"


// NB: there is only one panda json log
// so these fns dont return a Pandalog or pass one as a param
void pandalog_open(const char *path, const char *mode);
int  pandalog_close(void);

// write this element to pandpog.
// "asid", "pc", instruction count key/values
// b/c those will get added by this fn
void pandalog_write_entry(Panda__LogEntry *entry);

// read this element from pandalog.
// allocates memory, which caller will free
Panda__LogEntry *pandalog_read_entry(void);

// Must call this to free the entry returned by pandalog_read_entry
void pandalog_free_entry(Panda__LogEntry *entry);

extern int pandalog;

#endif


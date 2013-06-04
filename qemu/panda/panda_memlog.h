/* PANDABEGINCOMMENT PANDAENDCOMMENT */

#ifndef PANDA_MEMLOG_H
#define PANDA_MEMLOG_H

#include "inttypes.h"

/*
 * File-based logging
 */

void printloc(uintptr_t);
void printdynval(uintptr_t, int);
void printramaddr(uintptr_t, int);
void open_memlog(char *path);
void close_memlog(void);

/*
 * Dynamic logging
 */

typedef enum {
    LOAD,
    STORE,
    BRANCHOP,
    SELECT,
    SWITCH
} LogOp;

typedef struct dyn_val_buffer_struct {
    char *start;
    uint32_t max_size;
    uint32_t cur_size;
    char *ptr;
} DynValBuffer;

typedef enum {
    ADDRENTRY,
    BRANCHENTRY,
    SELECTENTRY,
    SWITCHENTRY,
    EXCEPTIONENTRY
} DynValEntryType;

#include "taint_processor.h"

typedef struct dyn_val_entry_struct {
    DynValEntryType entrytype;
    union {
        struct {LogOp op; Addr addr;} memaccess;
        struct {bool br;} branch;
        struct {bool sel;} select;
        struct {unsigned cond;} switchstmt;
    } entry;
} DynValEntry;

// Create a new DynValBuffer
DynValBuffer *create_dynval_buffer(uint32_t size);

// Destroy an old DynValBuffer
void delete_dynval_buffer(DynValBuffer *dynval_buf);

// Write an entry into a DynValBuffer
void write_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry);

// Read an entry from a DynValBuffer
void read_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry);

// Remove all entries from a DynValBuffer
void clear_dynval_buffer(DynValBuffer *dynval_buf);

// Rewind the pointer in a DynValBuffer back to the beginning
void rewind_dynval_buffer(DynValBuffer *dynval_buf);

// Log a dynamic value.  Called from guest code (translated or helper function).
void log_dynval(DynValBuffer *dynval_buf, DynValEntryType type, LogOp op,
    uintptr_t dynval);

// Log that an exception occured
void log_exception(DynValBuffer *dynval_buf);

#endif


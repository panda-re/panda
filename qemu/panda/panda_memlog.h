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

#ifndef PANDA_MEMLOG_H
#define PANDA_MEMLOG_H

#include <inttypes.h>

void open_memlog(char *path);
void close_memlog(void);

typedef enum {
    LOAD,
    PLOAD, // port load
    STORE,
    PSTORE, // port store
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
    PADDRENTRY, // for x86 I/O ports
    BRANCHENTRY,
    SELECTENTRY,
    SWITCHENTRY,
    EXCEPTIONENTRY
} DynValEntryType;


#include "panda_addr.h"
//#include "taint_processor.h"

typedef struct dyn_val_entry_struct {
    DynValEntryType entrytype;
    union {
        struct {LogOp op; Addr addr;} memaccess;
        struct {LogOp op; Addr addr;} portaccess;
        struct {bool br;} branch;
        struct {bool sel;} select;
        struct {int64_t cond;} switchstmt;
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

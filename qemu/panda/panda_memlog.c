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

#include "math.h"
#include "stdio.h"

#include "config.h"
#include "qemu-common.h"
#include "dyngen-exec.h"

#include "guestarch.h"
#include "panda_memlog.h"

FILE *memlog;

void open_memlog(char *path){
    memlog = fopen(path, "w");
}

void close_memlog(void){
    if (memlog){
        fclose(memlog);
        memlog = NULL;
    }
}

#ifdef CONFIG_LLVM // These functions are for LLVM code

bool regs_inited = false;

static void log_dyn_load(DynValBuffer *dynval_buf, uintptr_t dynval){
    if (unlikely(!regs_inited)){
        init_regs();
        regs_inited = true;
    }

    if (dynval == (uintptr_t)(&env)){
        // location of env is irrelevant
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        addr.typ = MADDR;
        addr.flag = IRRELEVANT;
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = LOAD;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
    else if ((dynval >= (uintptr_t)env) &&
            (dynval < ((uintptr_t)env + sizeof(CPUState)))){
        // inside of CPUState
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        int val = get_cpustate_val(dynval);
        if (val < 0){
            addr.flag = IRRELEVANT;
        }
        else if (val < NUMREGS){
            addr.typ = GREG;
            addr.val.gr = val;
        }
        else if (val >= NUMREGS){
            addr.typ = GSPEC;
            addr.val.gs = val;
        }
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = LOAD;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
    else {
        // else, must be a memory address
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        addr.typ = MADDR;
        addr.val.ma = dynval;
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = LOAD;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
}

static void log_dyn_store(DynValBuffer *dynval_buf, uintptr_t dynval){
    if (unlikely(!regs_inited)){
        init_regs();
        regs_inited = true;
    }

    if (dynval == (uintptr_t)(&env)){
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        addr.typ = MADDR;
        addr.flag = IRRELEVANT;
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = STORE;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
    else if ((dynval >= (uintptr_t)env) &&
            (dynval < ((uintptr_t)env + sizeof(CPUState)))){
        // inside of CPUState
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        int val = get_cpustate_val(dynval);
        if (val < 0){
            addr.flag = IRRELEVANT;
        }
        else if (val <= NUMREGS){
            addr.typ = GREG;
            addr.val.gr = val;
        }
        else if (val > NUMREGS){
            addr.typ = GSPEC;
            addr.val.gs = val;
        }
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = STORE;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
    else {
        // else, must be a memory address
        DynValEntry dventry;
        memset(&dventry, 0, sizeof(DynValEntry));
        Addr addr;
        memset(&addr, 0, sizeof(Addr));
        addr.typ = MADDR;
        addr.val.ma = dynval;
        dventry.entrytype = ADDRENTRY;
        dventry.entry.memaccess.op = STORE;
        dventry.entry.memaccess.addr = addr;
        write_dynval_buffer(dynval_buf, &dventry);
    }
}

#endif // CONFIG_LLVM

DynValBuffer *create_dynval_buffer(uint32_t size){
    DynValBuffer *buf = (DynValBuffer *) my_malloc(sizeof(DynValBuffer),
            poolid_dynamic_log);
    buf->max_size = size;
    buf->start = (char *) my_malloc(size, poolid_dynamic_log);
    buf->ptr = buf->start;
    return buf;
}

void delete_dynval_buffer(DynValBuffer *dynval_buf){
    my_free(dynval_buf->start, dynval_buf->max_size, poolid_dynamic_log);
    dynval_buf->start = NULL;
    my_free(dynval_buf, sizeof(DynValBuffer), poolid_dynamic_log);
    dynval_buf = NULL;
}

void write_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry){
    uint32_t bytes_used = dynval_buf->ptr - dynval_buf->start;
    assert(dynval_buf->max_size - bytes_used >= sizeof(DynValEntry));
    memcpy(dynval_buf->ptr, entry, sizeof(DynValEntry));
    dynval_buf->ptr += sizeof(DynValEntry);
    dynval_buf->cur_size = dynval_buf->ptr - dynval_buf->start;
}

void read_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry){
    uint32_t bytes_used = dynval_buf->ptr - dynval_buf->start;
    assert(dynval_buf->max_size - bytes_used >= sizeof(DynValEntry));
    memcpy(entry, dynval_buf->ptr, sizeof(DynValEntry));
    dynval_buf->ptr += sizeof(DynValEntry);
}

void clear_dynval_buffer(DynValBuffer *dynval_buf){
    dynval_buf->ptr = dynval_buf->start;
    dynval_buf->cur_size = 0;
}

void rewind_dynval_buffer(DynValBuffer *dynval_buf){
    dynval_buf->ptr = dynval_buf->start;
}

#ifdef CONFIG_LLVM // This function is for LLVM code

void log_dynval(DynValBuffer *dynval_buf, DynValEntryType type, LogOp op,
        uintptr_t dynval){
    assert(dynval_buf);
    DynValEntry dventry;
    memset(&dventry, 0, sizeof(DynValEntry));
    if (dynval_buf){
        switch (type){
            case ADDRENTRY:
                if (op == LOAD){
                    log_dyn_load(dynval_buf, dynval);
                }
                else if (op == STORE){
                    log_dyn_store(dynval_buf, dynval);
                }
                break;

            case BRANCHENTRY:
                dventry.entrytype = BRANCHENTRY;
                dventry.entry.branch.br = dynval;
                write_dynval_buffer(dynval_buf, &dventry);
                break;

            case SELECTENTRY:
                dventry.entrytype = SELECTENTRY;
                dventry.entry.select.sel = dynval;
                write_dynval_buffer(dynval_buf, &dventry);
                break;

            case SWITCHENTRY:
                dventry.entrytype = SWITCHENTRY;
                dventry.entry.switchstmt.cond = dynval;
                write_dynval_buffer(dynval_buf, &dventry);
                break;

            default:
                break;
        }
    }
}

#endif // CONFIG_LLVM

void log_exception(DynValBuffer *dynval_buf){
    assert(dynval_buf);
    DynValEntry dventry;
    memset(&dventry, 0, sizeof(DynValEntry));
    dventry.entrytype = EXCEPTIONENTRY;
    write_dynval_buffer(dynval_buf, &dventry);
}


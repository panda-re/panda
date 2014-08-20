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

#include <math.h>
#include <stdio.h>

extern"C" {
#include "config.h"
#include "qemu-common.h"
#include "dyngen-exec.h"
}

#include "guestarch.h"
#include "panda_memlog.h"
#include "panda_common.h"
#include "tubtf.h"
//#include "taint_processor.h"
#include "panda_addr.h"

extern TubtfTrace *tubtf;

// if this is 1 then we log tubtf style
// otherwise the DynvalEntry struct is just blitted to file
extern int tubtf_on;

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
        else if (val < NUMREGS){
            addr.typ = GREG;
            addr.val.gr = val;
        }
        else if (val >= NUMREGS){
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

static void log_paddr(DynValBuffer *dynval_buf, uintptr_t dynval, uint32_t op){
    if (unlikely(!regs_inited)){
        init_regs();
        regs_inited = true;
    }
    DynValEntry dventry;
    memset(&dventry, 0, sizeof(DynValEntry));
    Addr addr;
    memset(&addr, 0, sizeof(Addr));
    addr.typ = PADDR;
    addr.val.pa = dynval;
    dventry.entrytype = PADDRENTRY;
    dventry.entry.portaccess.op = (LogOp) op;
    dventry.entry.portaccess.addr = addr;
    write_dynval_buffer(dynval_buf, &dventry);
}

#endif // CONFIG_LLVM

DynValBuffer *create_dynval_buffer(uint32_t size){
    DynValBuffer *buf = (DynValBuffer *) malloc(sizeof(DynValBuffer));
    buf->max_size = size;
    buf->cur_size = 0;
    buf->start = (char *) malloc(size);
    buf->ptr = buf->start;
    return buf;
}

void delete_dynval_buffer(DynValBuffer *dynval_buf){
    free(dynval_buf->start) ; //, dynval_buf->max_size);
    dynval_buf->start = NULL;
    free(dynval_buf); //  sizeof(DynValBuffer), poolid_dynamic_log);
    dynval_buf = NULL;
}



void write_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry){
    if (tubtf_on) {
        // XXX Fixme: note that when using tubt format, we still create that DynValBuffer.  Waste of memory
        uint64_t cr3, pc, typ;
        uint64_t arg1, arg2, arg3, arg4;
        arg1 = arg2 = arg3 = arg4 = 0;
        assert (tubtf->colw == TUBTF_COLW_64);
        uint32_t element_size = tubtf_element_size();
        // assert that there must be enough room in dynval buffer
        uint32_t bytes_used = dynval_buf->ptr - dynval_buf->start;
        uint32_t bytes_left = dynval_buf->max_size - bytes_used;
        assert (bytes_left > element_size);
        cr3 = panda_current_asid(env);  // virtual address space -- cr3 for x86
        pc = panda_current_pc(env);
        typ = 0;
        switch (entry->entrytype) {
            case ADDRENTRY:
                {
                    LogOp op = entry->entry.memaccess.op;
                    assert (op == LOAD ||op == STORE);
                    Addr *a = &(entry->entry.memaccess.addr);
                    typ = TUBTFE_LLVM_DV_LOAD;
                    if (op == STORE) {
                        typ = TUBTFE_LLVM_DV_STORE;
                    }
                    // a->type fits easily in a byte -- 1 .. 5
                    arg1 = (a->typ) | ((a->flag & 0xff) << 8) | (a->off << 16);
                    uint64_t val;

                    switch (a->typ) {
                        case HADDR:
                            val = a->val.ha;
                            break;
                        case MADDR:
                            val = a->val.ma;
                            break;
                        case IADDR:
                            val = a->val.ia;
                            break;
                        case LADDR:
                            val = a->val.la;
                            break;
                        case GREG:
                            val = a->val.gr;
                            break;
                        case GSPEC:
                            val = a->val.gs;
                            break;
                        case UNK:
                            val = a->val.ua;
                            break;
                        case CONST:
                            val = a->val.con;
                            break;
                        case RET:
                            val = a->val.ret;
                            break;
                        default:
                            assert (1==0);
                    }
                    arg2 = val;
                    break;
                }
            case PADDRENTRY:
                {
                    LogOp op = entry->entry.portaccess.op;
                    assert (op == PLOAD ||op == PSTORE);
                    Addr *a = &(entry->entry.portaccess.addr);
                    typ = TUBTFE_LLVM_DV_LOAD;
                    if (op == STORE) {
                        typ = TUBTFE_LLVM_DV_STORE;
                    }
                    // a->type fits easily in a byte -- 1 .. 5
                    arg1 = (a->typ) | ((a->flag & 0xff) << 8) | (a->off << 16);
                    uint64_t val;

                    switch (a->typ) {
                        case PADDR:
                            val = a->val.pa;
                            break;
                        default:
                            assert (1==0);
                    }
                    arg2 = val;
                    break;
                }
            case BRANCHENTRY:
                {
                    typ = TUBTFE_LLVM_DV_BRANCH;
                    arg1 = entry->entry.branch.br;
                    break;
                }
            case SELECTENTRY:
                {
                    typ = TUBTFE_LLVM_DV_SELECT;
                    arg1 = entry->entry.select.sel;
                    break;
                }
            case SWITCHENTRY:
                {
                    typ = TUBTFE_LLVM_DV_SWITCH;
                    arg1 = entry->entry.switchstmt.cond;
                    break;
                }
            case EXCEPTIONENTRY:
                {
                    typ = TUBTFE_LLVM_EXCEPTION;
                }
        }
        tubtf_write_el_64(cr3, pc, typ, arg1, arg2, arg3, arg4);
    }
    else {
        uint32_t bytes_used = dynval_buf->ptr - dynval_buf->start;
        assert(dynval_buf->max_size - bytes_used >= sizeof(DynValEntry));
        memcpy(dynval_buf->ptr, entry, sizeof(DynValEntry));
        dynval_buf->ptr += sizeof(DynValEntry);
        dynval_buf->cur_size = dynval_buf->ptr - dynval_buf->start;
    }
}



void read_dynval_buffer(DynValBuffer *dynval_buf, DynValEntry *entry){
    assert (tubtf_on == 0);
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

            case PADDRENTRY:
                if (op == PLOAD || op == PSTORE){
                    log_paddr(dynval_buf, dynval, op);
                }
                else {
                    assert(1==0);
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


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

#include "panda_common.h"

#include "tubtf.h"
#include "taint_processor.h"

extern TubtfTrace *tubtf;

// if this is 1 then we log tubtf style
// otherwise the DynvalEntry struct is just blitted to file
extern int tubtf_on;




/******************************************************************************
 * File-based logging
 * FIXME: log DynValEntries instead of strings from now on, and have trace
 * processor use that instead.
 *****************************************************************************/

FILE *memlog;

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

void printloc(uintptr_t val){
    if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EAX])){
        fprintf(memlog, "%d\n", R_EAX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ECX])){
        fprintf(memlog, "%d\n", R_ECX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EDX])){
        fprintf(memlog, "%d\n", R_EDX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EBX])){
        fprintf(memlog, "%d\n", R_EBX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ESP])){
        fprintf(memlog, "%d\n", R_ESP);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EBP])){
        fprintf(memlog, "%d\n", R_EBP);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ESI])){
        fprintf(memlog, "%d\n", R_ESI);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EDI])){
        fprintf(memlog, "%d\n", R_EDI);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_op)){
        fprintf(memlog, "%d\n", CC_OP_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_src)){
        fprintf(memlog, "%d\n", CC_SRC_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_dst)){
        fprintf(memlog, "%d\n", CC_DST_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, eip)){
        fprintf(memlog, "%d\n", EIP_REG);
    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)
                + (sizeof(XMMReg) * CPU_NB_REGS)))){
        // inside XMM regs
        // print the proper enum to be used by the trace analyzer

        // get XMM register
        int xmmreg =
            floor(((val - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0])))
            / sizeof(XMMReg)));
        // get offset within register
        int xmmoff =
            (val - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0]))) %
            sizeof(XMMReg);
        // get enum that can be be processed by trace analyzer
        int xmmenum = XMMREGS_0_0 + xmmreg*16 + xmmoff;

        fprintf(memlog, "%d\n", xmmenum);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)
                + sizeof(XMMReg)))){
        // inside xmm_t0
        // print the proper enum to be used by the trace analyzer
        fprintf(memlog, "%lu\n", val - ((uintptr_t)env +
            offsetof(CPUX86State, xmm_t0)) + XMM_T0_0);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)
                + sizeof(MMXReg)))){
        // inside mmx_t0
        // print the proper enum to be used by the trace analyzer
        fprintf(memlog, "%lu\n", val - ((uintptr_t)env +
            offsetof(CPUX86State, mmx_t0)) + MMX_T0_0);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, fpregs)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, fpregs)
                + (sizeof(FPReg) * 8)))){
        // inside FP regs
        // print the proper enum as seen above to be used by the trace analyzer

        // get FP register
        int fpreg =
            floor(((val - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) /
            sizeof(FPReg)));
        // get offset within register
        int fpoff =
            (val - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) %
            sizeof(FPReg);
        // get enum that can be be processed by trace analyzer
        int fpenum = FPREGS_0_0 + fpreg*10 + fpoff;

        fprintf(memlog, "%d\n", fpenum);
    }

    // exception occurred
    else if (val == 0xDEADBEEF){
        fprintf(memlog, "%lu\n", val);
    }

    else {
        fprintf(memlog, "-1\n");
    }
}
#endif //TARGET_I386

#ifdef TARGET_X86_64

void printloc(uintptr_t val){
    if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EAX])){
        fprintf(memlog, "%d\n", R_EAX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ECX])){
        fprintf(memlog, "%d\n", R_ECX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EDX])){
        fprintf(memlog, "%d\n", R_EDX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EBX])){
        fprintf(memlog, "%d\n", R_EBX);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ESP])){
        fprintf(memlog, "%d\n", R_ESP);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EBP])){
        fprintf(memlog, "%d\n", R_EBP);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_ESI])){
        fprintf(memlog, "%d\n", R_ESI);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R_EDI])){
        fprintf(memlog, "%d\n", R_EDI);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R8])){
        fprintf(memlog, "%d\n", R8);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R9])){
        fprintf(memlog, "%d\n", R9);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R10])){
        fprintf(memlog, "%d\n", R10);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R11])){
        fprintf(memlog, "%d\n", R11);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R12])){
        fprintf(memlog, "%d\n", R12);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R13])){
        fprintf(memlog, "%d\n", R13);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R14])){
        fprintf(memlog, "%d\n", R14);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, regs[R15])){
        fprintf(memlog, "%d\n", R15);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_op)){
        fprintf(memlog, "%d\n", CC_OP_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_src)){
        fprintf(memlog, "%d\n", CC_SRC_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, cc_dst)){
        fprintf(memlog, "%d\n", CC_DST_REG);
    } else if (val == ((uintptr_t)env) + offsetof(CPUX86State, eip)){
        fprintf(memlog, "%d\n", RIP_REG);
    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, xmm_regs)
                + (sizeof(XMMReg) * CPU_NB_REGS)))){
        // inside XMM regs
        // print the proper enum to be used by the trace analyzer

        // get XMM register
        int xmmreg =
            floor(((val - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0])))
            / sizeof(XMMReg)));
        // get offset within register
        int xmmoff =
            (val - ((uintptr_t)env + offsetof(CPUX86State, xmm_regs[0]))) %
            sizeof(XMMReg);
        // get enum that can be be processed by trace analyzer
        int xmmenum = XMMREGS_0_0 + xmmreg*16 + xmmoff;

        fprintf(memlog, "%d\n", xmmenum);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, xmm_t0)
                + sizeof(XMMReg)))){
        // inside xmm_t0
        // print the proper enum to be used by the trace analyzer
        fprintf(memlog, "%lu\n", val - ((uintptr_t)env +
            offsetof(CPUX86State, xmm_t0)) + XMM_T0_0);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, mmx_t0)
                + sizeof(MMXReg)))){
        // inside mmx_t0
        // print the proper enum to be used by the trace analyzer
        fprintf(memlog, "%lu\n", val - ((uintptr_t)env +
            offsetof(CPUX86State, mmx_t0)) + MMX_T0_0);

    } else if ((val >= (((uintptr_t)env) + offsetof(CPUX86State, fpregs)))
            && (val < (((uintptr_t)env) + offsetof(CPUX86State, fpregs)
                + (sizeof(FPReg) * 8)))){
        // inside FP regs
        // print the proper enum as seen above to be used by the trace analyzer

        // get FP register
        int fpreg =
            floor(((val - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) /
            sizeof(FPReg)));
        // get offset within register
        int fpoff =
            (val - ((uintptr_t)env + offsetof(CPUX86State, fpregs[0]))) %
            sizeof(FPReg);
        // get enum that can be be processed by trace analyzer
        int fpenum = FPREGS_0_0 + fpreg*10 + fpoff;

        fprintf(memlog, "%d\n", fpenum);
    }

    // exception occurred
    else if (val == 0xDEADBEEF){
        //printf("deadbeef\n");
        fprintf(memlog, "%lu\n", val);
    }

    else {
        fprintf(memlog, "-1\n");
        //printf("0x%x\n", val);
    }
}
#endif //TARGET_X86_64

#ifdef TARGET_ARM

void printloc(uintptr_t val){
    if ((val >= ((uintptr_t)env + offsetof(CPUARMState, regs[0]))) &&
            (val <= ((uintptr_t)env + offsetof(CPUARMState, regs[15])))){
        fprintf(memlog, "%d\n",
            (int)(val - (uintptr_t)(env + offsetof(CPUARMState, regs))) / 4);
    }
    
    // exception occurred
    else if (val == 0xDEADBEEF){
        fprintf(memlog, "%lu\n", val);
    }

    else {
        fprintf(memlog, "-1\n");
    }
}

#endif //TARGET_ARM

void printdynval(uintptr_t val, int op){
    if (memlog){
        if (op == STORE){
            fprintf(memlog, "store ");
            printloc(val);
        } else if (op == LOAD){
            fprintf(memlog, "load ");
            printloc(val);
        } else if (op == BRANCHOP){
            fprintf(memlog, "condbranch %lu\n", val);
        } else if (op == SELECT){
            fprintf(memlog, "select %lu\n", val);
        }
    }
}

/* For whole-system mode, make sure you pass in the physical address for taint
 * analysis.  For user-mode, we log the virtual address.
 */
void printramaddr(uintptr_t physaddr, int store){
    if (memlog){
        if (store == 1){
            fprintf(memlog, "store %lu\n", physaddr);
        } else if (store == 0){
            fprintf(memlog, "load %lu\n", physaddr);
        }
    }
}

void open_memlog(char *path){
    memlog = fopen(path, "w");
}

void close_memlog(void){
    if (memlog){
        fclose(memlog);
        memlog = NULL;
    }
}

/******************************************************************************
 * Dynamic logging
 *****************************************************************************/

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
        else {
            addr.typ = GREG;
            addr.val.gr = get_cpustate_val(dynval);
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
        else {
            addr.typ = GREG;
            addr.val.gr = get_cpustate_val(dynval);
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


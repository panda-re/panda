/* PANDABEGINCOMMENT
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <memory>
#include <string>
#include <unordered_map>

#include "panda/plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include <iostream>
using namespace std;

// Is this a reasonable max strlen for a syscall arg? 
#define MAX_STRLEN 128


int get_string(CPUState *cpu, target_ulong addr, uint8_t *buf) {
    // determine strlen (upto max)
    int len = 0;
    uint8_t c;
    while (len < MAX_STRLEN) {
        int rv = panda_virtual_memory_read(cpu, addr + len, (uint8_t*) (&c), 1);
        if (rv == -1) break;
        if (c == 0) break;
        len ++;
    }
    if (len > 0) {
        int rv = panda_virtual_memory_read(cpu, addr, (uint8_t*) buf, len);
        buf[len] = 0;
        for (int i=0; i<len; i++) 
            if (!isprint(buf[i])) buf[i] = '.';
        assert (rv != -1);
    }
    return len;
}     


void sys_return(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp) {

    OsiProc *current = NULL;
    OsiThread *othread = NULL;

    // need to have current proc / thread
    current =  get_current_process(cpu); 
    if (current == NULL || current->pid == 0) 
        return;

    othread = get_current_thread(cpu);
    if (othread == NULL) 
        return;

    uint8_t buf[MAX_STRLEN];
    if (pandalog) {
        Panda__Syscall psyscall;
        psyscall = PANDA__SYSCALL__INIT;
        psyscall.pid = current->pid;
        psyscall.ppid = current->ppid;
        psyscall.tid = othread->tid;
        psyscall.create_time = current->create_time;
        psyscall.call_name = strdup(call->name);
        psyscall.args = (Panda__SyscallArg **) malloc (sizeof(Panda__SyscallArg *) * call->nargs);
        for (int i=0; i<call->nargs; i++) {
            Panda__SyscallArg *sa = (Panda__SyscallArg *) malloc(sizeof(Panda__SyscallArg));
            psyscall.args[i] = sa;
            *sa = PANDA__SYSCALL_ARG__INIT;
            switch (call->argt[i]) {                
            case SYSCALL_ARG_STR:
            {
                target_ulong addr = *((target_ulong *)rp->args[i]);
                int len = get_string(cpu, addr, buf);
                if (len > 0) {
                    sa->str = strdup((const char *) buf);
                }
                else {
                    sa->str = strdup("n/a");                    
                }
//                sa->has_str = true;
                break;
            }
            case SYSCALL_ARG_PTR:
                sa->ptr = (uint64_t) *((target_ulong *) rp->args[i]);
                sa->has_ptr = true;
                break;

            case SYSCALL_ARG_U64:
                sa->u64 = (uint64_t) *((target_ulong *) rp->args[i]);
                sa->has_u64 = true;
                break;

            case SYSCALL_ARG_U32:
                sa->u32 = *((uint32_t *) rp->args[i]);
                sa->has_u32 = true;
                break;
 
            case SYSCALL_ARG_U16:
                sa->u16 = (uint32_t) *((uint16_t *) rp->args[i]);
                sa->has_u16 = true;
                break;
 
            case SYSCALL_ARG_S64:
                sa->i64 = *((int64_t *) rp->args[i]);
                sa->has_i64 = true;
                break;
           
            case SYSCALL_ARG_S32:
                sa->i32 = *((int32_t *) rp->args[i]);
                sa->has_i32 = true;
                break;
 
            case SYSCALL_ARG_S16:
                sa->i16 = (int32_t) *((int16_t *) rp->args[i]);
                sa->has_i16 = true;
                break;
            
            default:
                break;
            }
        }
        psyscall.n_args = call->nargs;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.syscall = &psyscall;
        ple.has_asid = true;
        ple.asid = current->asid;
        pandalog_write_entry(&ple);
        for (int i=0; i<call->nargs; i++) 
            free(psyscall.args[i]);
        free(psyscall.args);
    }
    else {        
        cout << "proc [pid=" << current->pid << ",ppid=" << current->ppid
             << ",tid=" << othread->tid << ",create_time=" << current->create_time
             << ",name=" << current->name << "]\n";
        cout << " syscall ret pc=" << hex << pc << " name=" << call->name << "\n";
        
        for (int i=0; i<call->nargs; i++) {            
            cout << "  arg " << i ;
            switch (call->argt[i]) {
            case SYSCALL_ARG_STR:
            {
                target_ulong addr = *((target_ulong *)rp->args[i]);
                int len = get_string(cpu, addr, buf);
                cout << " str[";
                if (len > 0) 
                    cout << buf;
                cout << "]\n";
                break;
            }
            case SYSCALL_ARG_PTR:
                cout << "ptr[" << hex << (*((target_ulong *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_U64:
                cout << "u64[" << (*((uint64_t *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_U32:
                cout << "u32[" << (*((uint32_t *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_U16:
                cout << "u16[" << (*((uint16_t *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_S64:
                cout << "i64[" << (*((int64_t *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_S32:
                cout << "i32[" << (*((int32_t *) rp->args[i])) << "]\n";
                break;
                
            case SYSCALL_ARG_S16:
                cout << "i16[" << (*((int16_t *) rp->args[i])) << "]\n";
                break;
                
            default:
                break;
                
            }
        }
    }
}



bool init_plugin(void *self)
{

    // this is required in order to use the on_all_sys_[enter|return]2 cbs
    panda_add_arg("syscalls2", "load-info=1");
    panda_require("syscalls2");
    assert(init_syscalls2_api());
    
    panda_require("osi");
    assert(init_osi_api());

//    PPP_REG_CB("syscalls2", on_all_sys_enter2, sys_enter);
    PPP_REG_CB("syscalls2", on_all_sys_return2, sys_return);


    return true;
}

void uninit_plugin(void *self) {
    // intentionally left blank
}

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


// This module tracks the file names associated with file descriptors.
// It currently DOES NOT handle links AT ALL
// It tracks open(), etc., so only knows the names used by those functions

#if defined(SYSCALLS_FDS_TRACK_LINKS)
#error "Hard and soft links are not supported"
#endif

#include <map>
#include <string>
#include "weak_callbacks.hpp"
#include "syscalls.hpp"

extern "C" {
#include <fcntl.h>
}

const target_ulong NULL_FD = 0;

using namespace std;


typedef map<int, string> fdmap;

map<target_ulong, fdmap> asid_to_fds;

class OpenCallbackData : public CallbackData {
public:
    string path;
    target_ulong base_fd;
};

static target_ulong calc_retaddr(CPUState* env, target_ulong pc){
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    return env->regs[14];
    // Fork, exec
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    return pc + offset;
#elif defined(TARGET_I386)
    
#else
    
#endif
}

//mkdirs
void call_sys_mkdirat_callback(CPUState* env,target_ulong pc,uint32_t dfd,std::string pathname,uint32_t mode) { 
    
}

void call_sys_mkdir_callback(CPUState* env,target_ulong pc,std::string pathname,uint32_t mode) { 
    
}
//opens

static void open_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    OpenCallbackData* data = dynamic_cast<OpenCallbackData*>(opaque);
    if (-1 == get_return_val(env)){
        return;
    }
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    string dirname = "";
    auto& mymap = asid_to_fds[asid];
    
    if(NULL_FD != data->base_fd){
        dirname += mymap[data->base_fd];
    }
    dirname += "/" + data->path;
    mymap[get_return_val(env)] = dirname;
}

void call_sys_open_callback(CPUState *env, target_ulong pc, std::string filename,uint32_t flags,uint32_t mode){
    OpenCallbackData* data = new OpenCallbackData;
    data->path = filename;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));
}

void call_sys_openat_callback(CPUState* env,target_ulong pc,uint32_t dfd,std::string filename,uint32_t flags,uint32_t mode){
    OpenCallbackData* data = new OpenCallbackData;
    data->path = filename;
    data->base_fd = dfd;
    if (dfd == AT_FDCWD)
        data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));
    
}

// dups

// close


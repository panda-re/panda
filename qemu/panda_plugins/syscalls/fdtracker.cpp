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
#include <iostream>

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

class DupCallbackData: public CallbackData {
public:
    target_ulong old_fd;
    target_ulong new_fd;
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

//mkdirs
void call_sys_mkdirat_callback(CPUState* env,target_ulong pc,uint32_t dfd,std::string pathname,uint32_t mode) { 
    //mkdirat does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData;
    data->path = pathname;
    data->base_fd = dfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}

void call_sys_mkdir_callback(CPUState* env,target_ulong pc,std::string pathname,uint32_t mode) { 
    // mkdir does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData;
    data->path = pathname;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}
//opens

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

static void dup_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    DupCallbackData* data = dynamic_cast<DupCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    target_ulong new_fd;
    if(data->new_fd != NULL_FD){
        new_fd = data->new_fd;
    }else{
        new_fd = get_return_val(env);
    }
    asid_to_fds[asid][new_fd] = asid_to_fds[asid][data->old_fd];
}

// dups
void call_sys_dup_callback(CPUState* env,target_ulong pc,uint32_t fildes) {
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = fildes;
    data->new_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}
void call_sys_dup2_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd) { 
    target_asid asid = get_asid(env, pc);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
    
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = oldfd;
    data->new_fd = newfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}
void call_sys_dup3_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd,uint32_t flags) {
    target_asid asid = get_asid(env, pc);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
    
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = oldfd;
    data->new_fd = newfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}

// close
void call_sys_close_callback(CPUState* env,target_ulong pc,uint32_t fd) { }

void call_sys_readahead_callback(CPUState* env,target_ulong pc,uint32_t fd,uint64_t offset,uint32_t count) { }

void call_sys_read_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    cout << "Reading from " << asid_to_fds[asid][fd] << endl;
}
void call_sys_readv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) { 
    target_asid asid = get_asid(env, pc);
    cout << "Reading v from " << asid_to_fds[asid][fd] << endl;
}
void call_sys_pread64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
        target_asid asid = get_asid(env, pc);
        cout << "Reading p64 from " << asid_to_fds[asid][fd] << endl;
}
void call_sys_write_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    cout << "Writing to " << asid_to_fds[asid][fd] << endl;
}
void call_sys_pwrite64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) { 
    target_asid asid = get_asid(env, pc);
    cout << "Writing pv64 to " << asid_to_fds[asid][fd] << endl;
}
void call_sys_writev_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
    target_asid asid = get_asid(env, pc);
    cout << "Writing v to " << asid_to_fds[asid][fd] << endl;
}

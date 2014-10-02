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

// FDTRACKER_ENABLE_TAINT does what it says

#if defined(SYSCALLS_FDS_TRACK_LINKS)
#error "Hard and soft links are not supported"
#endif

#include <map>
#include <string>
#include <list>
#include "callbacks.hpp"
#include "syscalls.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>

extern "C" {
#include <fcntl.h>
#include "panda_plugin.h"
#include "../taint/taint_ext.h"

    // struct iovec is {void* p, size_t len} which is target-specific
//TODO: fail on 64-bit ARM
    // Thankfully we are on an x86 host and don't need to worry about packing
    struct target_iovec{
        target_ulong base;
        target_ulong len;
    } __attribute__((packed));
}

static const bool TRACK_TAINT =
#if defined(FDTRACKER_ENABLE_TAINT)
 true;
#else
 false;
#endif

const target_long NULL_FD = -1;

using namespace std;

typedef map<int, string> fdmap;

map<target_ulong, fdmap> asid_to_fds;

/*declare this so we can call it in the static initializer after the fork tracker and
 * define it at the end of the file after all the callbacks have been declared */
static void registerSyscallListeners(void);

#if defined(CONFIG_PANDA_VMI)
extern "C" {
#include "introspection/DroidScope/LinuxAPI.h"
// sched.h contains only preprocessor defines to constant literals
#include <linux/sched.h>
}

//#define TEST_FORK
#ifdef TEST_FORK
map<target_ulong, bool> tracked_forks;
#endif

// copy any descriptors from parent ASID to child ASID that aren't set in child
static void copy_fds(target_asid parent_asid, target_asid child_asid){
    for(auto parent_mapping : asid_to_fds[parent_asid]){
        auto child_it = asid_to_fds[child_asid].find(parent_mapping.first);
        if (child_it == asid_to_fds[child_asid].end()){
            asid_to_fds[child_asid][parent_mapping.first] = parent_mapping.second;
        }
    }
}

list<target_asid> outstanding_child_asids;
map<target_ulong, target_asid> outstanding_child_pids;


/* Deal with all scheduling cases:
 * - Parent returns first: PID of child is logged for copying
 * - Child returns first, not in VMI table yet: ASID is logged for copy at next chance
 * - Child returns first, in VMI table: copy will occur when parent returns :)
 * - Parent returns 
 * 
 * - parent runs first, child runs second but this callback runs 
 *      BEFORE the VMI can register the child process
 */
static int return_from_fork(CPUState *env){
    target_long child_pid = get_return_val(env);
    if(0 == child_pid){
        // This IS the child!
        assert("return_from_fork should only ever be called for the parent!");
        target_asid  asid;
        target_ulong pc;
        target_ulong cs_base;
        int flags;
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        asid = get_asid(env, pc);
        // See if the VMI can tell us our PID
        ProcessInfo* self_child = findProcessByPGD(asid);
        if(nullptr == self_child){
            // no, we can't look up our PID yet
            outstanding_child_asids.push_back(get_asid(env, pc));
        }else{
            auto it = outstanding_child_pids.find(self_child->pid);
            if (it == outstanding_child_pids.end()){
                outstanding_child_asids.push_back(get_asid(env, pc));
            }else{
                target_asid parent_asid = it->second;
                copy_fds(parent_asid, asid);
                outstanding_child_pids.erase(it);
            }
        }
        return 0;
    }

    // returned to the parent
    ProcessInfo* child = findProcessByPID(child_pid);
    if(nullptr == child){
        // child hasn't run yet!
        target_ulong pc;
        target_ulong cs_base;
        int flags;
        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        // log that this ASID is the parent of the child's PID
        outstanding_child_pids[child_pid] = get_asid(env, pc);
#ifdef TEST_FORK
        tracked_forks[child_pid] = false;
#endif
        return 0;
    }
    //we're in the parent and the child has run
    target_ulong pc;
    target_ulong cs_base;
    int flags;
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    copy_fds(get_asid(env, pc), child->pgd);
    outstanding_child_asids.remove(child->pgd);
#ifdef TEST_FORK
    tracked_forks[child_pid] = true;
#endif
    return 0;
}

static void preExecForkCopier(CPUState* env, target_ulong pc){
#ifdef TEST_FORK
    for(auto fork : tracked_forks){
        cout << "Forked process " << fork.first << ": " << fork.second << endl;
    }
#endif
    //is this process in outstanding_child_pids?
    if (outstanding_child_pids.empty()) {
        return;
    }
    target_asid my_asid = get_asid(env, pc);
    ProcessInfo* my_proc = findProcessByPGD(my_asid);
    if(nullptr == my_proc){
        // VMI doen't know about me yet... weird
        return;
    }
    auto it = outstanding_child_pids.find(my_proc->pid);
    if (it == outstanding_child_pids.end()){
        return;
    }
    // this is a process we're looking for!
    copy_fds(it->second, my_asid);
    outstanding_child_pids.erase(it);
#ifdef TEST_FORK
    tracked_forks[my_proc->pid] = true;
#endif
}

//#define TEST_CLONE
#ifdef TEST_CLONE
map<target_ulong, bool> tracked_clones;
#endif


/* Clone is weird. We don't care about all of them.
   Instead of registering an AFTER_CLONE callback, we'll just
   use the plugin's internal callback mechanism so we can skip ones
   we don't want (which are distinguished by the arguments)*/

class CloneCallbackData : public CallbackData {   
};

list<target_asid> outstanding_clone_child_asids;
map<target_ulong, target_asid> outstanding_clone_child_pids;

static Callback_RC clone_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    CloneCallbackData* data = dynamic_cast<CloneCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    // return value is TID = PID of child
    target_long child_pid = get_return_val(env);
    if(0 == child_pid){
        // I am the child.
        // This should never happen
        cerr << "Called after-clone callback in child, not parent!" << endl;
    } else if (-1 == child_pid){
        // call failed
    } else {
        ProcessInfo* child = findProcessByPID(child_pid);
        if(nullptr == child){
            // child hasn't run yet!
            target_ulong pc;
            target_ulong cs_base;
            int flags;
            cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

            // log that this ASID is the parent of the child's PID
            outstanding_clone_child_pids[child_pid] = asid;
#ifdef TEST_CLONE
            tracked_clones[child_pid] = false;
#endif
        } else {
            //we're in the parent and the child has run
            target_ulong pc;
            target_ulong cs_base;
            int flags;
            cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
            // sanity check: make sure it's really a new process, not a thread
            if(child->pgd == asid){
                cerr << "Attempted to track a clone that was thread-like" << endl;
                return Callback_RC::NORMAL;
            }
            copy_fds(asid, child->pgd);
            outstanding_clone_child_asids.remove(child->pgd);
#ifdef TEST_CLONE
            tracked_clones[child_pid] = true;
#endif
        }
    }
    return Callback_RC::NORMAL;
}

// if flags includes CLONE_FILES then the parent and child will continue to share a single FD table
// if flags includes CLONE_THREAD, then we don't care about the call.
static void fdtracker_call_clone_callback(CPUState* env,target_ulong pc,uint32_t clone_flags,uint32_t newsp,
                         target_ulong parent_tidptr,int32_t tls_val,
                         target_ulong child_tidptr,target_ulong regs) {
    if (CLONE_THREAD & clone_flags){
        return;
    }
    if (CLONE_FILES & clone_flags){
        cerr << "ERROR ERROR UNIMPLEMENTED!" << endl;
    }
    CloneCallbackData *data = new CloneCallbackData;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, clone_callback));
}

static void preExecCloneCopier(CPUState* env, target_ulong pc){
#ifdef TEST_CLONE
    for(auto clone : tracked_clones){
        cout << "Cloned process " << clone.first << ": " << clone.second << endl;
    }
#endif
    //is this process in outstanding_child_pids?
    if (outstanding_clone_child_pids.empty()) {
        return;
    }
    target_asid my_asid = get_asid(env, pc);
    ProcessInfo* my_proc = findProcessByPGD(my_asid);
    if(nullptr == my_proc){
        // VMI doen't know about me yet... weird
        return;
    }
    auto it = outstanding_clone_child_pids.find(my_proc->pid);
    if (it == outstanding_clone_child_pids.end()){
        return;
    }
    // this is a process we're looking for!
    copy_fds(it->second, my_asid);
    outstanding_clone_child_pids.erase(it);
#ifdef TEST_CLONE
    tracked_clones[my_proc->pid] = true;
#endif
}

/* hack to integrate the fork and clone tracker code with
   the syscalls plugin at startup, without modifying the plugin proper */
struct StaticBlock {
    StaticBlock(){
        registerExecPreCallback(preExecForkCopier);
        registerExecPreCallback(preExecCloneCopier);
        syscalls::register_call_clone(fdtracker_call_clone_callback);
        panda_cb pcb;

        pcb.return_from_fork = return_from_fork;
        panda_register_callback(syscalls_plugin_self, PANDA_CB_VMI_AFTER_FORK, pcb);
#else //defined CONFIG_PANDA_VMI
struct StaticBlock {
    StaticBlock(){
        cerr << "WARNING: CONFIG_PANDA_VMI is not defined. File descriptors will not be tracked across clone and fork!" << endl;
#endif //defined CONFIG_PANDA_VMI
        if(TRACK_TAINT){
            init_taint_api();
        }
        registerSyscallListeners();
    }
};
static StaticBlock staticBlock;

static ofstream    fdlog("/scratch/fdlog.txt");

class OpenCallbackData : public CallbackData {
public:
    syscalls::string path;
    target_long base_fd;
    OpenCallbackData(syscalls::string& apath): path(apath) {}
};

class DupCallbackData: public CallbackData {
public:
    target_long old_fd;
    target_long new_fd;
};

class ReadCallbackData : public CallbackData {
public:
    target_ulong fd;
    target_ulong guest_buffer;
    uint32_t len;
    target_ulong iovec_base;
    enum class ReadType {
        READ,
        READV,
    } type;
};


static const char* getName(target_asid asid){
    const char* comm = "";
#ifdef CONFIG_PANDA_VMI
    ProcessInfo* me = findProcessByPGD(asid);
    if(me){
        if(me->strName[0] != '\0')
            comm = me->strName;
        else
            comm = findProcessByPGD(asid)->strComm;
    }
#endif
    return comm;
}

static Callback_RC open_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    OpenCallbackData* data = dynamic_cast<OpenCallbackData*>(opaque);
    if (-1 == get_return_val(env)){
        return Callback_RC::NORMAL;
    }
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    string dirname = "";
    auto& mymap = asid_to_fds[asid];
    
    if(NULL_FD != data->base_fd){
        dirname += mymap[data->base_fd];
    }
    dirname += "/" + data->path.value();
    if(dirname.length() > 1 &&
        dirname[0] == '/' && dirname[1] == '/')
        dirname.erase(0,1); //remove leading slash
    mymap[get_return_val(env)] = dirname;
    const char* comm = getName(asid);
    if (NULL_FD != data->base_fd)
        dirname += " using OPENAT";
    fdlog << "Process " << comm << " opened " << dirname << " as FD " << get_return_val(env) <<  endl;
    return Callback_RC::NORMAL;
}

//mkdirs
static void fdtracker_sys_mkdirat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string pathname,int32_t mode) { 
    //mkdirat does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData(pathname);
    data->path = pathname;
    data->base_fd = dfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}

static void fdtracker_sys_mkdir_callback(CPUState* env,target_ulong pc,syscalls::string pathname,int32_t mode) { 
    // mkdir does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData(pathname);
    data->path = pathname;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}
//opens

static void fdtracker_sys_open_callback(CPUState *env, target_ulong pc, syscalls::string filename,int32_t flags,int32_t mode){
    OpenCallbackData* data = new OpenCallbackData(filename);
    data->path = filename;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));
}

static void fdtracker_sys_openat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,int32_t flags,int32_t mode){
    OpenCallbackData* data = new OpenCallbackData(filename);
    data->path = filename;
    data->base_fd = dfd;
    if (dfd == AT_FDCWD)
        data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));
}

static Callback_RC dup_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    DupCallbackData* data = dynamic_cast<DupCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    target_ulong new_fd;
    if(data->new_fd != NULL_FD){
        new_fd = data->new_fd;
    }else{
        new_fd = get_return_val(env);
    }
    const char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " duplicating FD for " << asid_to_fds[asid].at(data->old_fd) << " to " << new_fd << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing dup source FD " << data->old_fd << " to " << new_fd<< endl;
    }
    asid_to_fds[asid][new_fd] = asid_to_fds[asid][data->old_fd];
    return Callback_RC::NORMAL;
}

// dups
static void fdtracker_sys_dup_callback(CPUState* env,target_ulong pc,uint32_t fildes) {
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = fildes;
    data->new_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}
static void fdtracker_sys_dup2_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd) { 
    target_asid asid = get_asid(env, pc);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
    
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = oldfd;
    data->new_fd = newfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}
static void fdtracker_sys_dup3_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd,int32_t flags) {
    target_asid asid = get_asid(env, pc);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
    
    DupCallbackData* data = new DupCallbackData;
    data->old_fd = oldfd;
    data->new_fd = newfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    
}

// close
static void fdtracker_sys_close_callback(CPUState* env,target_ulong pc,uint32_t fd) {
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " closed " << asid_to_fds[asid].at(fd) << " FD " << fd << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing closing FD " << fd << endl;
    }
    
}

static void fdtracker_sys_readahead_callback(CPUState* env,target_ulong pc,int32_t fd,uint64_t offset,uint32_t count) { }

/* Apply taint to all bytes in the buffer */
static void taintify(target_ulong guest_vaddr, uint32_t len, uint32_t label, bool autoenc) {
    taint_enable_taint();
    for(uint32_t i = 0; i < len; i++){
        target_ulong va = guest_vaddr + i;
        target_phys_addr_t pa = cpu_get_phys_addr(cpu_single_env, va);
        if (autoenc)
            taint_label_ram(pa, i + label);
        else
            taint_label_ram(pa, label);
    }
}

/* Check if any of the bytes in the buffer are tainted */
static bool check_taint(target_ulong guest_vaddr, uint32_t len){
    if(1 != taint_enabled()){
        return false;
    }
    for(uint32_t i = 0; i < len; i++){
        target_ulong va = guest_vaddr + i;
        target_phys_addr_t pa = cpu_get_phys_addr(cpu_single_env, va);
        if(taint_query_ram(pa))
            return true;
    }
    return false;
}

static Callback_RC read_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    ReadCallbackData* data = dynamic_cast<ReadCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    string filename = asid_to_fds[asid][data->fd];
    if (filename.empty()){
        
    }
    auto retval = get_return_val(env);
    const char* comm = getName(asid);
    fdlog << "Process " << comm << " finished reading " << filename << " return value " << retval <<  endl;
    // if we don't want to taint this file, we're done
    const char* datadata = "/data/data";
    if (0 != filename.compare(0 /* start */,
                              strlen(datadata) /*len*/,
                              datadata) ) {
        return Callback_RC::NORMAL;
    }
    if(TRACK_TAINT){
        //if the taint engine isn't on, turn it on and re-translate the TB with LLVM
        if(1 != taint_enabled()){
            taint_enable_taint();
            return Callback_RC::INVALIDATE;
        }
        if(ReadCallbackData::ReadType::READV == data->type){
            for (uint32_t i = 0; i < data->len; i++){
                struct target_iovec tmp;
                panda_virtual_memory_rw(env, data->iovec_base+i, reinterpret_cast<uint8_t*>(&tmp), sizeof(tmp), 0);
                taintify(tmp.base, tmp.len, 0, true);
            }
        }else if(ReadCallbackData::ReadType::READ == data->type){
            taintify(data->guest_buffer, data->len, 0, true);
        }
    }
    return Callback_RC::NORMAL;
}

static void fdtracker_sys_read_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "Reading from " << name << endl;
    ReadCallbackData *data = new ReadCallbackData;
    data->fd = fd;
    data->type = ReadCallbackData::ReadType::READ;
    data->guest_buffer = buf;
    data->len = count;    
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, read_callback));
}
static void fdtracker_sys_readv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) { 
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string filename = "";
    try{
        filename = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Reading v from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing read FD " << fd << endl;
    }
    const char* datadata = "/data/data";
    if (0 == filename.compare(0 /* start */,
                              strlen(datadata) /*len*/,
                              datadata) ) {
        // We want to taint this, but don't implement things yet
        cerr << "WARN: Readv called on " << filename << endl;
    }
    ReadCallbackData *data = new ReadCallbackData;
    data->fd = fd;
    data->iovec_base = vec;
    data->type = ReadCallbackData::ReadType::READV;
    data->len = vlen;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, read_callback));
}
static void fdtracker_sys_pread64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Reading p64 from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing readp FD " << fd << endl;
    }
    ReadCallbackData *data = new ReadCallbackData;
    data->fd = fd;
    data->type = ReadCallbackData::ReadType::READ;
    data->guest_buffer = buf;
    data->len = count;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, read_callback));
}

ofstream devnull("/scratch/nulls");
static void fdtracker_sys_write_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "Writing to " << name << endl;
    if (0 == name.compare("/dev/null") || 0 == name.compare("//dev/null")){
        uint8_t mybuf[count];
        panda_virtual_memory_rw(env, buf, mybuf, count, 0);
        devnull << mybuf << endl;
    }
    if(TRACK_TAINT){
        if(check_taint(buf, count)){
            fdlog << "Process " << comm << "  sending tainted data to " << name << endl;
        }
    }
}
static void fdtracker_sys_pwrite64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) { 
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    try{
        name = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Writing pv64 to " << name << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writep FD " << fd << endl;
    }
    if(TRACK_TAINT){
        if(check_taint(buf, count)){
            fdlog << "Process " << comm << "  sending tainted data to " << name << endl;
        }
    }
}
static void fdtracker_sys_writev_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    try{
        name = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Writing v to " << name << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writev FD " << fd << endl;
    }

    if(TRACK_TAINT){
        for (uint32_t i = 0; i < vlen; i++){
            struct target_iovec tmp;
            panda_virtual_memory_rw(env, vec+i, reinterpret_cast<uint8_t*>(&tmp), sizeof(tmp), 0);
            if(check_taint(tmp.base, tmp.len)){
                fdlog << "Process " << comm << "  sending tainted data to " << name << endl;
            }
        }
    }
}

/* Sockpair() handling code code is also used for pipe() and must be
 * outside the ifdef(SYSCALLS_FDS_TRACK_SOCKETS)'d region */
class SockpairCallbackData : public CallbackData{
public:
    target_ulong sd_array;
    uint32_t domain;
};
static Callback_RC sockpair_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    SockpairCallbackData* data = dynamic_cast<SockpairCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    target_long retval = get_return_val(env);
    //"On success, zero is returned.  On error, -1 is returned, and errno is set appropriately."
    if(0 != retval){
        return Callback_RC::NORMAL;
    }
    // sd_array is an array of ints, length 2. NOT target_ulong
    int sd_array[2];
    // On Linux, sizeof(int) != sizeof(long)
    panda_virtual_memory_rw(env, data->sd_array, reinterpret_cast<uint8_t*>(sd_array), 2*sizeof(int), 0);
    const char* comm = getName(asid);
    fdlog << "Creating pipe in process " << comm << endl;
    asid_to_fds[asid][sd_array[0]] = "<pipe>";
    asid_to_fds[asid][sd_array[1]] = "<pipe>";
    return Callback_RC::NORMAL;
}

#define SYSCALLS_FDS_TRACK_SOCKETS
#if defined(SYSCALLS_FDS_TRACK_SOCKETS)
// SOCKET OPERATIONS --------------------------------------------------------------------
// AF_UNIX, AF_LOCAL, etc
#include <sys/socket.h>
//kernel source says sa_family_t is an unsigned short

typedef map<int, sa_family_t> sdmap;

map<target_ulong, sdmap> asid_to_sds;

class SocketCallbackData : public CallbackData{
public:
    string socketname;
    sa_family_t domain;
};

static Callback_RC socket_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    SocketCallbackData* data = dynamic_cast<SocketCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    target_long new_sd = get_return_val(env);
    auto& mymap = asid_to_fds[asid];
    mymap[new_sd] = data->socketname;
    if(AF_UNSPEC != data->domain){
        auto& mysdmap = asid_to_sds[asid];
        mysdmap[new_sd] = data->domain;
    }
    return Callback_RC::NORMAL;
}

/*
bind - updates name?
struct sockaddr {
               sa_family_t sa_family;
               char        sa_data[14];
           }
*/
static void fdtracker_sys_bind_callback(CPUState* env,target_ulong pc,int32_t sockfd,target_ulong sockaddr_ptr,int32_t sockaddrlen){
    const char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " binding FD " << sockfd << endl;   
}
/*
connect - updates name?
*/
static void fdtracker_sys_connect_callback(CPUState* env,target_ulong pc,int32_t sockfd,target_ulong sockaddr_ptr,int32_t sockaddrlen){
    const char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " connecting FD " << sockfd << endl;
}
/*
socket - fd
Return value should be labeled "unbound socket"
*/
static void fdtracker_sys_socket_callback(CPUState* env,target_ulong pc,int32_t domain,int32_t type,int32_t protocol){
    SocketCallbackData* data = new SocketCallbackData;
    data->socketname = "unbound socket";
    data->domain = domain;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, socket_callback));
}
/*
send, sendto, sendmsg - */
static void fdtracker_sys_send_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t arg3){
    fdtracker_sys_write_callback(env, pc, fd,buf, len);
}
static void fdtracker_sys_sendto_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t arg3,target_ulong arg4,uint32_t arg5){
    fdtracker_sys_write_callback(env, pc, fd,buf, len);   
}
static void fdtracker_sys_sendmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "sending msg to " << name << endl;  
}

/*recv, recvfrom, recvmsg - gets datas!*/
static void fdtracker_sys_recvmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = get_asid(env, pc);
    const char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "recving msg from " << name << endl;
}
static void fdtracker_sys_recvfrom_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t flags,target_ulong arg4,target_ulong arg5){
    fdtracker_sys_read_callback(env, pc, fd, buf, len);
}
static void fdtracker_sys_recv_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t flags){
    fdtracker_sys_read_callback(env, pc, fd, buf, len);
}
/*listen
socketpair - two new fds
*/
static void fdtracker_sys_socketpair_callback(CPUState* env,target_ulong pc,int32_t domain,int32_t type,int32_t protocol,target_ulong sd_array){
    SockpairCallbackData *data = new SockpairCallbackData;
    data->domain = domain;
    data->sd_array = sd_array;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sockpair_callback));
}
/*
accept, accept4 - new fd*/
class AcceptCallbackData : public CallbackData{
public:
    
};

static Callback_RC accept_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    AcceptCallbackData* data = dynamic_cast<AcceptCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return Callback_RC::ERROR;
    }
    target_long retval = get_return_val(env);
    if (-1 == retval){
        return Callback_RC::NORMAL;
    }
    asid_to_fds[asid][retval]= "SOCKET ACCEPTED";
    return Callback_RC::NORMAL;
}

static void fdtracker_sys_accept_callback(CPUState* env,target_ulong pc,int32_t sockfd,target_ulong arg1,target_ulong arg2) { 
    const char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " accepting on FD " << sockfd << endl;
    AcceptCallbackData* data = new AcceptCallbackData;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, accept_callback));
}
#endif // SYSCALLS_FDS_TRACK_SOCKETS

static void fdtracker_sys_pipe_callback(CPUState* env,target_ulong pc,target_ulong arg0){
    SockpairCallbackData *data = new SockpairCallbackData;
    data->domain = 0;
    data->sd_array = arg0;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sockpair_callback));
}
static void fdtracker_sys_pipe2_callback(CPUState* env,target_ulong pc,target_ulong arg0,int32_t arg1){
    SockpairCallbackData *data = new SockpairCallbackData;
    data->domain = 0;
    data->sd_array = arg0;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sockpair_callback));
}
//static void fdtracker_sys_truncate_callback(CPUState* env,target_ulong pc,syscalls::string path,uint32_t length);
//static void fdtracker_sys_ftruncate_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t length);
/*cmd == F_DUPFD, returns new fd
  cmd == F_DUPFD_CLOEXEC same */
static void fdtracker_sys_fcntl_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg){
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC){
        DupCallbackData* data = new DupCallbackData;
        data->old_fd = fd;
        data->new_fd = NULL_FD;
        appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    }
}
static void fdtracker_sys_sendfile64_callback(CPUState* env,target_ulong pc,int32_t out_fd,int32_t in_fd,target_ulong offset,uint32_t count){
    target_asid asid = get_asid(env, pc);
    const char* conn = getName(asid);
    fdlog << conn << " copying data from " << asid_to_fds[asid][in_fd] << " to " << asid_to_fds[asid][out_fd] << endl;
}

void registerSyscallListeners(void)
{
    syscalls::register_call_sys_mkdirat(fdtracker_sys_mkdirat_callback);
    syscalls::register_call_sys_mkdir(fdtracker_sys_mkdir_callback);
    syscalls::register_call_sys_open(fdtracker_sys_open_callback);
    syscalls::register_call_sys_openat(fdtracker_sys_openat_callback);
    syscalls::register_call_sys_dup(fdtracker_sys_dup_callback);
    syscalls::register_call_sys_dup2(fdtracker_sys_dup2_callback);
    syscalls::register_call_sys_dup3(fdtracker_sys_dup3_callback);
    syscalls::register_call_sys_close(fdtracker_sys_close_callback);
    syscalls::register_call_sys_read(fdtracker_sys_read_callback);
    syscalls::register_call_sys_readv(fdtracker_sys_readv_callback);
    syscalls::register_call_sys_pread64(fdtracker_sys_pread64_callback);
    syscalls::register_call_sys_write(fdtracker_sys_write_callback);
    syscalls::register_call_sys_writev(fdtracker_sys_writev_callback);
    syscalls::register_call_sys_pwrite64(fdtracker_sys_pwrite64_callback);
#if defined(SYSCALLS_FDS_TRACK_SOCKETS)
    syscalls::register_call_sys_bind(fdtracker_sys_bind_callback);
    syscalls::register_call_sys_connect(fdtracker_sys_connect_callback);
    syscalls::register_call_sys_socket(fdtracker_sys_socket_callback);
    syscalls::register_call_sys_send(fdtracker_sys_send_callback);
    syscalls::register_call_sys_sendto(fdtracker_sys_sendto_callback);
    syscalls::register_call_sys_sendmsg(fdtracker_sys_sendmsg_callback);
    syscalls::register_call_sys_recvmsg(fdtracker_sys_recvmsg_callback);
    syscalls::register_call_sys_recvfrom(fdtracker_sys_recvfrom_callback);
    syscalls::register_call_sys_recv(fdtracker_sys_recv_callback);
    syscalls::register_call_sys_socketpair(fdtracker_sys_socketpair_callback);
    syscalls::register_call_sys_accept(fdtracker_sys_accept_callback);
#endif
    syscalls::register_call_sys_pipe(fdtracker_sys_pipe_callback);
    syscalls::register_call_sys_pipe2(fdtracker_sys_pipe2_callback);
    syscalls::register_call_sys_fcntl(fdtracker_sys_fcntl_callback);
    syscalls::register_call_sys_sendfile64(fdtracker_sys_sendfile64_callback);
}

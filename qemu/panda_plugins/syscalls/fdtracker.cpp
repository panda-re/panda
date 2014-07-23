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
#include <list>
#include "weak_callbacks.hpp"
#include "syscalls.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>

extern "C" {
#include <fcntl.h>
#include "panda_plugin.h"
}

const target_ulong NULL_FD = 0;

using namespace std;

static target_ulong calc_retaddr(CPUState* env, target_ulong pc){
#if defined(TARGET_ARM)
    // Normal syscalls: return addr is stored in LR
    return mask_retaddr_to_pc(env->regs[14]);

    // Fork, exec
    uint8_t offset = 0;
    if(env->thumb == 0){
        offset = 4;
    } else {
        offset = 2;
    }
    return pc + offset;
#elif defined(TARGET_I386)
#error "return address calculation not implemented for x86 in fdtracker"
#else
#error "return address calculation not implemented for this architecture in fdtracker"
#endif
}

typedef map<int, string> fdmap;

map<target_ulong, fdmap> asid_to_fds;

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
    target_ulong child_pid = get_return_val(env);
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

static void clone_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    CloneCallbackData* data = dynamic_cast<CloneCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    // return value is TID = PID of child
    target_ulong child_pid = get_return_val(env);
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
                return;
            }
            copy_fds(asid, child->pgd);
            outstanding_clone_child_asids.remove(child->pgd);
#ifdef TEST_CLONE
            tracked_clones[child_pid] = true;
#endif
        }
    }
}

// if flags includes CLONE_FILES then the parent and child will continue to share a single FD table
// if flags includes CLONE_THREAD, then we don't care about the call.
void call_clone_callback(CPUState* env,target_ulong pc,uint32_t clone_flags,uint32_t newsp,
                         target_ulong parent_tidptr,uint32_t tls_val,
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
        panda_cb pcb;

        pcb.return_from_fork = return_from_fork;
        panda_register_callback(syscalls_plugin_self, PANDA_CB_VMI_AFTER_FORK, pcb);
    }
};
static StaticBlock staticBlock;
#else //defined CONFIG_PANDA_VMI
struct StaticBlock {
    StaticBlock(){
        cerr << "WARNING: CONFIG_PANDA_VMI is not defined. File descriptors will not be tracked across clone and fork!" << endl;
    }
};
static StaticBlock staticBlock;

#endif //defined CONFIG_PANDA_VMI

static ofstream    fdlog("/scratch/fdlog.txt");

class OpenCallbackData : public CallbackData {
public:
    syscalls::string path;
    target_ulong base_fd;
    OpenCallbackData(syscalls::string& apath): path(apath) {}
};

class DupCallbackData: public CallbackData {
public:
    target_ulong old_fd;
    target_ulong new_fd;
};

class ReadCallbackData : public CallbackData {
public:
    target_ulong fd;
    target_ulong guest_buffer;
    uint32_t len;
};


static char* getName(target_asid asid){
    char* comm = "";
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
    dirname += "/" + data->path.value();
    if(dirname.length() > 1 &&
        dirname[0] == '/' && dirname[1] == '/')
        dirname.erase(0,1); //remove leading slash
    mymap[get_return_val(env)] = dirname;
    char* comm = getName(asid);
    if (NULL_FD != data->base_fd)
        dirname += " using OPENAT";
    fdlog << "Process " << comm << " opened " << dirname << " as FD " << get_return_val(env) <<  endl;
}

//mkdirs
void call_sys_mkdirat_callback(CPUState* env,target_ulong pc,uint32_t dfd,syscalls::string pathname,uint32_t mode) { 
    //mkdirat does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData(pathname);
    data->path = pathname;
    data->base_fd = dfd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}

void call_sys_mkdir_callback(CPUState* env,target_ulong pc,syscalls::string pathname,uint32_t mode) { 
    // mkdir does not return an FD
    /*OpenCallbackData* data = new OpenCallbackData(pathname);
    data->path = pathname;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));*/
}
//opens

void call_sys_open_callback(CPUState *env, target_ulong pc, syscalls::string filename,uint32_t flags,uint32_t mode){
    OpenCallbackData* data = new OpenCallbackData(filename);
    data->path = filename;
    data->base_fd = NULL_FD;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, open_callback));
}

void call_sys_openat_callback(CPUState* env,target_ulong pc,uint32_t dfd,syscalls::string filename,uint32_t flags,uint32_t mode){
    OpenCallbackData* data = new OpenCallbackData(filename);
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
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " duplicating FD for " << asid_to_fds[asid].at(data->old_fd) << " to " << new_fd << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing dup source FD " << data->old_fd << " to " << new_fd<< endl;
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
void call_sys_close_callback(CPUState* env,target_ulong pc,uint32_t fd) {
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " closed " << asid_to_fds[asid].at(fd) << " FD " << fd << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing closing FD " << fd << endl;
    }
    
}

void call_sys_readahead_callback(CPUState* env,target_ulong pc,uint32_t fd,uint64_t offset,uint32_t count) { }

static void read_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    ReadCallbackData* data = dynamic_cast<ReadCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    string filename = asid_to_fds[asid][data->fd];
    if (filename.empty()){
        
    }
    auto retval = get_return_val(env);
    char* comm = getName(asid);
    fdlog << "Process " << comm << " finished reading " << filename << " return value " << retval <<  endl;
}

void call_sys_read_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "Reading from " << name << endl;
    ReadCallbackData *data = new ReadCallbackData;
    data->fd = fd;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, read_callback));
}
void call_sys_readv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) { 
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Reading v from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing read FD " << fd << endl;
    }
}
void call_sys_pread64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Reading p64 from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing readp FD " << fd << endl;
    }
}

ofstream devnull("/scratch/nulls");
void call_sys_write_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
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
}
void call_sys_pwrite64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) { 
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Writing pv64 to " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writep FD " << fd << endl;
    }
}
void call_sys_writev_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Writing v to " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writev FD " << fd << endl;
    }
}

/* Sockpair() handling code code is also used for pipe() and must be
 * outside the ifdef(SYSCALLS_FDS_TRACK_SOCKETS)'d region */
class SockpairCallbackData : public CallbackData{
public:
    target_ulong sd_array;
    uint32_t domain;
};
static void sockpair_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    SockpairCallbackData* data = dynamic_cast<SockpairCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    target_ulong retval = get_return_val(env);
    //"On success, zero is returned.  On error, -1 is returned, and errno is set appropriately."
    if(0 != retval){
        return;
    }
    // sd_array is an array of ints, length 2. NOT target_ulong
    int sd_array[2];
    // On Linux, sizeof(int) != sizeof(long)
    panda_virtual_memory_rw(env, data->sd_array, reinterpret_cast<uint8_t*>(sd_array), 2*sizeof(int), 0);
    char* comm = getName(asid);
    fdlog << "Creating pipe in process " << comm << endl;
    asid_to_fds[asid][sd_array[0]] = "<pipe>";
    asid_to_fds[asid][sd_array[1]] = "<pipe>";
    
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

static void socket_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    SocketCallbackData* data = dynamic_cast<SocketCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    target_ulong new_sd = get_return_val(env);
    auto& mymap = asid_to_fds[asid];
    mymap[new_sd] = data->socketname;
    if(AF_UNSPEC != data->domain){
        auto& mysdmap = asid_to_sds[asid];
        mysdmap[new_sd] = data->domain;
    }
}

/*
bind - updates name?
struct sockaddr {
               sa_family_t sa_family;
               char        sa_data[14];
           }
*/
void call_sys_bind_callback(CPUState* env,target_ulong pc,uint32_t sockfd,target_ulong sockaddr_ptr,uint32_t sockaddrlen){
    char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " binding FD " << sockfd << endl;   
}
/*
connect - updates name?
*/
void call_sys_connect_callback(CPUState* env,target_ulong pc,uint32_t sockfd,target_ulong sockaddr_ptr,uint32_t sockaddrlen){
    char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " connecting FD " << sockfd << endl;
}
/*
socket - fd
Return value should be labeled "unbound socket"
*/
void call_sys_socket_callback(CPUState* env,target_ulong pc,uint32_t domain,uint32_t type,uint32_t protocol){
    SocketCallbackData* data = new SocketCallbackData;
    data->socketname = "unbound socket";
    data->domain = domain;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, socket_callback));
}
/*
send, sendto, sendmsg - */
void call_sys_send_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t len,uint32_t arg3){
    call_sys_write_callback(env, pc, fd,buf, len);
}
void call_sys_sendto_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t len,uint32_t arg3,target_ulong arg4,uint32_t arg5){
    call_sys_write_callback(env, pc, fd,buf, len);   
}
void call_sys_sendmsg_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "sending msg to " << name << endl;  
}

/*recv, recvfrom, recvmsg - gets datas!*/
void call_sys_recvmsg_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = get_asid(env, pc);
    char* comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "recving msg from " << name << endl;
}
void call_sys_recvfrom_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t len,uint32_t flags,target_ulong arg4,target_ulong arg5){
    call_sys_read_callback(env, pc, fd, buf, len);
}
void call_sys_recv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t len,uint32_t flags){
    call_sys_read_callback(env, pc, fd, buf, len);
}
/*listen
socketpair - two new fds
*/
void call_sys_socketpair_callback(CPUState* env,target_ulong pc,uint32_t domain,uint32_t type,uint32_t protocol,target_ulong sd_array){
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

static void accept_callback(CallbackData* opaque, CPUState* env, target_asid asid){
    AcceptCallbackData* data = dynamic_cast<AcceptCallbackData*>(opaque);
    if(!data){
        fprintf(stderr, "oops\n");
        return;
    }
    target_ulong retval = get_return_val(env);
    if (-1 == retval){
        return;
    }
    asid_to_fds[asid][retval]= "SOCKET ACCEPTED";
    
}

void call_sys_accept_callback(CPUState* env,target_ulong pc,uint32_t sockfd,target_ulong arg1,target_ulong arg2) { 
    char* conn = getName(get_asid(env, pc));
    fdlog << "Process " << conn << " accepting on FD " << sockfd << endl;
    AcceptCallbackData* data = new AcceptCallbackData;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, accept_callback));
}
#endif // SYSCALLS_FDS_TRACK_SOCKETS

void call_sys_pipe_callback(CPUState* env,target_ulong pc,target_ulong arg0){
    SockpairCallbackData *data = new SockpairCallbackData;
    data->domain = 0;
    data->sd_array = arg0;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sockpair_callback));
}
void call_sys_pipe2_callback(CPUState* env,target_ulong pc,target_ulong arg0,uint32_t arg1){
    SockpairCallbackData *data = new SockpairCallbackData;
    data->domain = 0;
    data->sd_array = arg0;
    appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sockpair_callback));
}
//void call_sys_truncate_callback(CPUState* env,target_ulong pc,syscalls::string path,uint32_t length);
//void call_sys_ftruncate_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t length);
/*cmd == F_DUPFD, returns new fd
  cmd == F_DUPFD_CLOEXEC same */
void call_sys_fcntl_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg){
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC){
        DupCallbackData* data = new DupCallbackData;
        data->old_fd = fd;
        data->new_fd = NULL_FD;
        appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, dup_callback));
    }
}
void call_sys_sendfile64_callback(CPUState* env,target_ulong pc,uint32_t out_fd,uint32_t in_fd,target_ulong offset,uint32_t count){
    target_asid asid = get_asid(env, pc);
    char* conn = getName(asid);
    fdlog << conn << " copying data from " << asid_to_fds[asid][in_fd] << " to " << asid_to_fds[asid][out_fd] << endl;
}

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
#include <vector>
#include "../syscalls/syscalls_common.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>

#include "panda/panda_common.h"

extern "C" {
#include <fcntl.h>
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../taint/taint_ext.h"
#include "../syscalls/syscalls_ext.h"
#include "gen_syscalls_ext_typedefs.h"

    // struct iovec is {void* p, size_t len} which is target-specific
//TODO: fail on 64-bit ARM
    // Thankfully we are on an x86 host and don't need to worry about packing
    struct target_iovec{
        target_ulong base;
        target_ulong len;
    } __attribute__((packed));

    bool init_plugin(void *self);
    void uninit_plugin(void *self);

}

static bool track_taint;

static const target_long NULL_FD = -1;

using std::map;
using std::list;
using std::vector;
using std::string;
using std::ofstream;

using std::cerr;
using std::endl;
using std::to_string;

typedef map<int, string> fdmap;

static ofstream fdlog("fdlog.txt");

map<target_ulong, fdmap> asid_to_fds;

#if defined(CONFIG_PANDA_VMI)
extern "C" {
#include "../linux_vmi/linux_vmi_ext.h"
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
        asid = panda_current_asid(env);
        // See if the VMI can tell us our PID
        ProcessInfo* self_child = findProcessByPGD(asid);
        if(nullptr == self_child){
            // no, we can't look up our PID yet
            outstanding_child_asids.push_back(panda_current_asid(env));
        }else{
            auto it = outstanding_child_pids.find(self_child->pid);
            if (it == outstanding_child_pids.end()){
                outstanding_child_asids.push_back(panda_current_asid(env));
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
        outstanding_child_pids[child_pid] = panda_current_asid(env);
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

    copy_fds(panda_current_asid(env), child->pgd);
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
    target_asid my_asid = panda_current_asid(env);
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

list<target_asid> outstanding_clone_child_asids;
map<target_ulong, target_asid> outstanding_clone_child_pids;

static Callback_RC clone_callback(CPUState* env, target_asid asid){
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
    clone_callback(env, panda_current_asid(env));
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
    target_asid my_asid = panda_current_asid(env);
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
#endif

/* Differentiate between read/pread and iovec-based readv */
enum class ReadType {
    READ,
    READV,
};


static std::string getName(target_asid asid){
    std::string comm = "";
#ifdef CONFIG_PANDA_VMI
    ProcessInfo* me = findProcessByPGD(asid);
    if(me){
        if(me->strName[0] != '\0')
            comm = me->strName;
        else
            comm = findProcessByPGD(asid)->strComm;
    }
#endif
    if (comm == "") {
        std::ostringstream s;
        s << "0x" << std::hex << asid;
        return s.str();
    }
    else return comm;
}

static Callback_RC open_callback(CPUState* env, target_asid asid, syscalls::string path, target_long base_fd){
    if (-1 == get_return_val(env)){
        return Callback_RC::NORMAL;
    }
    string dirname = "";
    auto& mymap = asid_to_fds[asid];

    if(NULL_FD != base_fd){
        dirname += mymap[base_fd];
    }
    dirname += "/" + path.value();
    if(dirname.length() > 1 &&
        dirname[0] == '/' && dirname[1] == '/')
        dirname.erase(0,1); //remove leading slash
    mymap[get_return_val(env)] = dirname;
    std::string comm = getName(asid);
    if (NULL_FD != base_fd)
        dirname += " using OPENAT";
    fdlog << "Process " << comm << " opened " << dirname << " as FD " << get_return_val(env) <<  endl;
    return Callback_RC::NORMAL;
}

static void fdtracker_sys_open_callback(CPUState *env, target_ulong pc, target_ulong filenameptr,int32_t flags,int32_t mode){
    syscalls::string filename(env, pc, filenameptr);
    open_callback(env, panda_current_asid(env), filename, NULL_FD);
}

static void fdtracker_sys_openat_callback(CPUState* env,target_ulong pc,int32_t dfd,target_ulong filenameptr,int32_t flags,int32_t mode){
    syscalls::string filename(env, pc, filenameptr);
    // ternary: translate syscall API constant for "current dir" to our constant for "current dir"
    open_callback(env, panda_current_asid(env), filename, (dfd == AT_FDCWD)? NULL_FD : dfd);
}

static Callback_RC dup_callback(CPUState* env, target_asid asid, target_ulong old_fd, target_long new_fd){
    if(new_fd == NULL_FD){
        new_fd = new_fd;
    }else{
        new_fd = get_return_val(env);
    }
    std::string comm = getName(asid);
    try{
        fdlog << "Process " << comm << " duplicating FD for " << asid_to_fds[asid].at(old_fd) << " to " << new_fd << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing dup source FD " << old_fd << " to " << new_fd<< endl;
    }
    asid_to_fds[asid][new_fd] = asid_to_fds[asid][old_fd];
    return Callback_RC::NORMAL;
}

// dups
static void fdtracker_sys_dup_callback(CPUState* env,target_ulong pc,uint32_t fildes) {
    dup_callback(env, panda_current_asid(env), fildes, NULL_FD);

}
static void fdtracker_sys_dup2_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd) {
    target_asid asid = panda_current_asid(env);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
}
static void fdtracker_sys_dup3_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd,int32_t flags) {
    target_asid asid = panda_current_asid(env);
    asid_to_fds[asid][newfd] = asid_to_fds[asid][oldfd];
    return;
}

// close
static void fdtracker_sys_close_callback(CPUState* env,target_ulong pc,uint32_t fd) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
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

static std::vector<std::string> read_fd_names;

const char *__fdtracker_get_fd_name(uint32_t taint_label) {
    std::string str(read_fd_names[taint_label]);
    return strdup(str.c_str());
}

extern "C" {
const char *fdtracker_get_fd_name(uint32_t taint_label) {
    return __fdtracker_get_fd_name(taint_label);
}
}

static Callback_RC read_callback(CPUState* env, target_asid asid, target_long fd,
                                 target_ulong guest_buffer, uint32_t len, ReadType type){
    string filename = asid_to_fds[asid][fd];
    if (filename.empty()){
        filename = string("UNKNOWN fd ") + to_string(fd);
    }
    auto retval = get_return_val(env);
    std::string comm = getName(asid);
    fdlog << "Process " << comm << " finished reading " << filename << " return value " << retval <<  endl;
    // if we don't want to taint this file, we're done
    if(track_taint){
        //if the taint engine isn't on, turn it on and re-translate the TB with LLVM
        if(1 != taint_enabled()){
            taint_enable_taint();
            return Callback_RC::INVALIDATE;
        }
        if(ReadType::READV == type){
            for (uint32_t i = 0; i < len; i++){
                struct target_iovec tmp;
                panda_virtual_memory_rw(env, guest_buffer+i, reinterpret_cast<uint8_t*>(&tmp), sizeof(tmp), 0);
                taintify(tmp.base, tmp.len, read_fd_names.size(), false);
            }
            read_fd_names.push_back(filename);
        }else if(ReadType::READ == type){
            uint32_t label = read_fd_names.size();
            taintify(guest_buffer, len, read_fd_names.size(), false);
            read_fd_names.push_back(filename);
            printf("tainted: label %u, vector size %u\n", label, read_fd_names.size());
        }
    }
    return Callback_RC::NORMAL;
}

#ifdef CONFIG_ANDROID
static const char *datadata = "/data/data";
#endif

static void fdtracker_sys_read_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0 && asid_to_fds[asid][fd].size() > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "Reading from " << name << endl;
#ifdef CONFIG_ANDROID
    if (0 == name.compare(0 /* start */,
                          strlen(datadata) /*len*/,
                          datadata) ) {
        // We want to taint this, but don't implement things yet
        cerr << "WARN: Readv called on " << name << endl;
    }
#endif
    read_callback(env, panda_current_asid(env), fd, buf, count, ReadType::READ);
}
static void fdtracker_sys_readv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    string filename = "";
    try{
        filename = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Reading v from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing read FD " << fd << endl;
    }
#ifdef CONFIG_ANDROID
    if (0 == filename.compare(0 /* start */,
                              strlen(datadata) /*len*/,
                              datadata) ) {
        // We want to taint this, but don't implement things yet
        cerr << "WARN: Readv called on " << filename << endl;
    }
#endif
    read_callback(env, panda_current_asid(env), fd, vec, vlen , ReadType::READV);
}
static void fdtracker_sys_pread64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    try{
        fdlog << "Process " << comm << " " << "Reading p64 from " << asid_to_fds[asid].at(fd) << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing readp FD " << fd << endl;
    }
    read_callback(env, panda_current_asid(env), fd, buf, count, ReadType::READ);
}

ofstream devnull("/scratch/nulls");
static void fdtracker_sys_write_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
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
    if(track_taint){
        if(check_taint(buf, count)){
            fdlog << "Process " << comm << "  sending tainted data to " << name << endl;
        }
    }
}
static void fdtracker_sys_pwrite64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    try{
        name = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Writing pv64 to " << name << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writep FD " << fd << endl;
    }
    if(track_taint){
        if(check_taint(buf, count)){
            fdlog << "Process " << comm << "  sending tainted data to " << name << endl;
        }
    }
}
static void fdtracker_sys_writev_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    try{
        name = asid_to_fds[asid].at(fd);
        fdlog << "Process " << comm << " " << "Writing v to " << name << endl;
    }catch( const std::out_of_range& oor){
        fdlog << "Process " << comm << " missing writev FD " << fd << endl;
    }

    if(track_taint){
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
static Callback_RC sockpair_callback(CPUState* env, target_asid asid, target_ulong sd_array_base, uint32_t domain){
    target_long retval = get_return_val(env);
    //"On success, zero is returned.  On error, -1 is returned, and errno is set appropriately."
    if(0 != retval){
        return Callback_RC::NORMAL;
    }
    // sd_array is an array of ints, length 2. NOT target_ulong
    int sd_array[2];
    // On Linux, sizeof(int) != sizeof(long)
    panda_virtual_memory_rw(env, sd_array_base, reinterpret_cast<uint8_t*>(sd_array), 2*sizeof(int), 0);
    std::string comm = getName(asid);
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

static Callback_RC socket_callback(CPUState* env, target_asid asid, string socketname, sa_family_t domain){
    target_long new_sd = get_return_val(env);
    auto& mymap = asid_to_fds[asid];
    mymap[new_sd] = socketname;
    if(AF_UNSPEC != domain){
        auto& mysdmap = asid_to_sds[asid];
        mysdmap[new_sd] = domain;
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
    std::string conn = getName(panda_current_asid(env));
    fdlog << "Process " << conn << " binding FD " << sockfd << endl;
}
/*
connect - updates name?
*/
static void fdtracker_sys_connect_callback(CPUState* env,target_ulong pc,int32_t sockfd,target_ulong sockaddr_ptr,int32_t sockaddrlen){
    std::string conn = getName(panda_current_asid(env));
    fdlog << "Process " << conn << " connecting FD " << sockfd << endl;
}
/*
socket - fd
Return value should be labeled "unbound socket"
*/
static void fdtracker_sys_socket_callback(CPUState* env,target_ulong pc,int32_t domain,int32_t type,int32_t protocol){
    socket_callback(env, panda_current_asid(env), "unbound socket", domain);
}
/*
send, sendto, sendmsg - */
static void fdtracker_sys_send_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t arg3){
    fdtracker_sys_write_callback(env, pc, fd,buf, len);
}
static void fdtracker_sys_sendto_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong buf,uint32_t len,uint32_t arg3,target_ulong arg4,int32_t arg5){
    fdtracker_sys_write_callback(env, pc, fd,buf, len);
}
static void fdtracker_sys_sendmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
    string name = string("UNKNOWN fd ") + to_string(fd);
    if (asid_to_fds[asid].count(fd) > 0){
        name =  asid_to_fds[asid][fd];
    }
    fdlog << "Process " << comm << " " << "sending msg to " << name << endl;
}

/*recv, recvfrom, recvmsg - gets datas!*/
static void fdtracker_sys_recvmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags){
    target_asid asid = panda_current_asid(env);
    std::string comm = getName(asid);
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
    sockpair_callback(env, panda_current_asid(env), sd_array, domain);
}
/*
accept, accept4 - new fd*/

static Callback_RC accept_callback(CPUState* env, target_asid asid){
    target_long retval = get_return_val(env);
    if (-1 == retval){
        return Callback_RC::NORMAL;
    }
    asid_to_fds[asid][retval]= "SOCKET ACCEPTED";
    return Callback_RC::NORMAL;
}

static void fdtracker_sys_accept_callback(CPUState* env,target_ulong pc,int32_t sockfd,target_ulong arg1,target_ulong arg2) {
    std::string conn = getName(panda_current_asid(env));
    fdlog << "Process " << conn << " accepting on FD " << sockfd << endl;
    accept_callback(env, panda_current_asid(env));
}
#endif // SYSCALLS_FDS_TRACK_SOCKETS

static void fdtracker_sys_pipe_callback(CPUState* env,target_ulong pc,target_ulong arg0){
    sockpair_callback(env, panda_current_asid(env), arg0, 0);
}
static void fdtracker_sys_pipe2_callback(CPUState* env,target_ulong pc,target_ulong arg0,int32_t arg1){
    sockpair_callback(env, panda_current_asid(env), arg0, 0);
}
//static void fdtracker_sys_truncate_callback(CPUState* env,target_ulong pc,syscalls::string path,uint32_t length);
//static void fdtracker_sys_ftruncate_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t length);
/*cmd == F_DUPFD, returns new fd
  cmd == F_DUPFD_CLOEXEC same */
static void fdtracker_sys_fcntl_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg){
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC){
        dup_callback(env, panda_current_asid(env), fd, NULL_FD);
    }
}
static void fdtracker_sys_sendfile64_callback(CPUState* env,target_ulong pc,int32_t out_fd,int32_t in_fd,target_ulong offset,uint32_t count){
    target_asid asid = panda_current_asid(env);
    std::string conn = getName(asid);
    fdlog << conn << " copying data from " << asid_to_fds[asid][in_fd] << " to " << asid_to_fds[asid][out_fd] << endl;
}

bool init_plugin(void *self)
{
    init_syscalls_api();
#ifdef CONFIG_PANDA_VMI
    registerExecPreCallback(preExecForkCopier);
    registerExecPreCallback(preExecCloneCopier);
    PPP_REG_CB("syscalls", on_clone_returned, fdtracker_call_clone_callback);
    panda_cb pcb;

    pcb.return_from_fork = return_from_fork;
    panda_register_callback(self, PANDA_CB_VMI_AFTER_FORK, pcb);

    init_linux_vmi_api();
#else //defined CONFIG_PANDA_VMI
    cerr << "WARNING: CONFIG_PANDA_VMI is not defined. File descriptors will not be tracked across clone and fork!" << endl;
#endif //defined CONFIG_PANDA_VMI

    panda_arg_list *args = panda_get_args("fdtracker");
    track_taint = panda_parse_bool(args, "taint");

    if(track_taint){
        init_taint_api();
        taint_enable_taint();
    }

    PPP_REG_CB("syscalls", on_sys_open_returned, fdtracker_sys_open_callback);
    PPP_REG_CB("syscalls", on_sys_openat_returned, fdtracker_sys_openat_callback);
    PPP_REG_CB("syscalls", on_sys_dup_returned, fdtracker_sys_dup_callback);
    PPP_REG_CB("syscalls", on_sys_dup2_returned, fdtracker_sys_dup2_callback);
    PPP_REG_CB("syscalls", on_sys_dup3_returned, fdtracker_sys_dup3_callback);
    PPP_REG_CB("syscalls", on_sys_close_returned, fdtracker_sys_close_callback);
    PPP_REG_CB("syscalls", on_sys_read_returned, fdtracker_sys_read_callback);
    PPP_REG_CB("syscalls", on_sys_readv_returned, fdtracker_sys_readv_callback);
    PPP_REG_CB("syscalls", on_sys_pread64_returned, fdtracker_sys_pread64_callback);
    PPP_REG_CB("syscalls", on_sys_write_returned, fdtracker_sys_write_callback);
    PPP_REG_CB("syscalls", on_sys_writev_returned, fdtracker_sys_writev_callback);
    PPP_REG_CB("syscalls", on_sys_pwrite64_returned, fdtracker_sys_pwrite64_callback);
#if defined(SYSCALLS_FDS_TRACK_SOCKETS) && !defined(TARGET_I386)
    PPP_REG_CB("syscalls", on_sys_bind_returned, fdtracker_sys_bind_callback);
    PPP_REG_CB("syscalls", on_sys_connect_returned, fdtracker_sys_connect_callback);
    PPP_REG_CB("syscalls", on_sys_socket_returned, fdtracker_sys_socket_callback);
    PPP_REG_CB("syscalls", on_sys_send_returned, fdtracker_sys_send_callback);
    PPP_REG_CB("syscalls", on_sys_sendto_returned, fdtracker_sys_sendto_callback);
    PPP_REG_CB("syscalls", on_sys_sendmsg_returned, fdtracker_sys_sendmsg_callback);
    PPP_REG_CB("syscalls", on_sys_recvmsg_returned, fdtracker_sys_recvmsg_callback);
    PPP_REG_CB("syscalls", on_sys_recvfrom_returned, fdtracker_sys_recvfrom_callback);
    PPP_REG_CB("syscalls", on_sys_recv_returned, fdtracker_sys_recv_callback);
    PPP_REG_CB("syscalls", on_sys_socketpair_returned, fdtracker_sys_socketpair_callback);
    PPP_REG_CB("syscalls", on_sys_accept_returned, fdtracker_sys_accept_callback);
#endif
    PPP_REG_CB("syscalls", on_sys_pipe_returned, fdtracker_sys_pipe_callback);
    PPP_REG_CB("syscalls", on_sys_pipe2_returned, fdtracker_sys_pipe2_callback);
    PPP_REG_CB("syscalls", on_sys_fcntl_returned, fdtracker_sys_fcntl_callback);
    PPP_REG_CB("syscalls", on_sys_sendfile64_returned, fdtracker_sys_sendfile64_callback);

    return true;
}

void uninit_plugin(void *self) {}

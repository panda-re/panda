
#include "callbacks.hpp"
extern "C"{
#include "cpu.h"
}

// weak-defined default empty callbacks for all syscalls
#ifdef TARGET_ARM
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_restart_syscall;
void syscalls::register_call_sys_restart_syscall(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_restart_syscall.push_back(callback);
}
struct sys_restart_syscall_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_restart_syscall_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_restart_syscall_calldata* data = dynamic_cast<sys_restart_syscall_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_restart_syscall_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_restart_syscall_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_restart_syscall){
    x(env,pc);
}
if (0 == ppp_on_sys_restart_syscall_returned_num_cb) return;
sys_restart_syscall_calldata* data = new sys_restart_syscall_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_restart_syscall_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_exit;
void syscalls::register_call_sys_exit(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_exit.push_back(callback);
}
struct sys_exit_calldata : public CallbackData {
target_ulong pc;
int32_t error_code;
};
static Callback_RC sys_exit_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_exit_calldata* data = dynamic_cast<sys_exit_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_exit_returned, env,data->pc,data->error_code)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_exit_callback(CPUState* env,target_ulong pc,int32_t error_code) {
for (auto x: internal_registered_callback_sys_exit){
    x(env,pc,error_code);
}
if (0 == ppp_on_sys_exit_returned_num_cb) return;
sys_exit_calldata* data = new sys_exit_calldata;
data->pc = pc;
data->error_code = error_code;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_exit_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_fork;
void syscalls::register_call_fork(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_fork.push_back(callback);
}
struct fork_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC fork_returned(CallbackData* opaque, CPUState* env, target_asid asid){
fork_calldata* data = dynamic_cast<fork_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_fork_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_fork_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_fork){
    x(env,pc);
}
if (0 == ppp_on_fork_returned_num_cb) return;
fork_calldata* data = new fork_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, fork_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_read;
void syscalls::register_call_sys_read(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_read.push_back(callback);
}
struct sys_read_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong buf;
uint32_t count;
};
static Callback_RC sys_read_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_read_calldata* data = dynamic_cast<sys_read_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_read_returned, env,data->pc,data->fd,data->buf,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_read_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
for (auto x: internal_registered_callback_sys_read){
    x(env,pc,fd,buf,count);
}
if (0 == ppp_on_sys_read_returned_num_cb) return;
sys_read_calldata* data = new sys_read_calldata;
data->pc = pc;
data->fd = fd;
data->buf = buf;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_read_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_write;
void syscalls::register_call_sys_write(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_write.push_back(callback);
}
struct sys_write_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong buf;
uint32_t count;
};
static Callback_RC sys_write_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_write_calldata* data = dynamic_cast<sys_write_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_write_returned, env,data->pc,data->fd,data->buf,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_write_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count) {
for (auto x: internal_registered_callback_sys_write){
    x(env,pc,fd,buf,count);
}
if (0 == ppp_on_sys_write_returned_num_cb) return;
sys_write_calldata* data = new sys_write_calldata;
data->pc = pc;
data->fd = fd;
data->buf = buf;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_write_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, int32_t)>> internal_registered_callback_sys_open;
void syscalls::register_call_sys_open(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, int32_t)> callback){
internal_registered_callback_sys_open.push_back(callback);
}
struct sys_open_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
int32_t flags;
int32_t mode;
};
static Callback_RC sys_open_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_open_calldata* data = dynamic_cast<sys_open_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_open_returned, env,data->pc,data->filename.get_vaddr(),data->flags,data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_open_callback(CPUState* env,target_ulong pc,syscalls::string filename,int32_t flags,int32_t mode) {
for (auto x: internal_registered_callback_sys_open){
    x(env,pc,filename,flags,mode);
}
if (0 == ppp_on_sys_open_returned_num_cb) return;
sys_open_calldata* data = new sys_open_calldata;
data->pc = pc;
data->filename = filename;
data->flags = flags;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_open_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_close;
void syscalls::register_call_sys_close(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_close.push_back(callback);
}
struct sys_close_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
};
static Callback_RC sys_close_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_close_calldata* data = dynamic_cast<sys_close_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_close_returned, env,data->pc,data->fd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_close_callback(CPUState* env,target_ulong pc,uint32_t fd) {
for (auto x: internal_registered_callback_sys_close){
    x(env,pc,fd);
}
if (0 == ppp_on_sys_close_returned_num_cb) return;
sys_close_calldata* data = new sys_close_calldata;
data->pc = pc;
data->fd = fd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_close_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_creat;
void syscalls::register_call_sys_creat(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_creat.push_back(callback);
}
struct sys_creat_calldata : public CallbackData {
target_ulong pc;
syscalls::string pathname;
int32_t mode;
};
static Callback_RC sys_creat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_creat_calldata* data = dynamic_cast<sys_creat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_creat_returned, env,data->pc,data->pathname.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_creat_callback(CPUState* env,target_ulong pc,syscalls::string pathname,int32_t mode) {
for (auto x: internal_registered_callback_sys_creat){
    x(env,pc,pathname,mode);
}
if (0 == ppp_on_sys_creat_returned_num_cb) return;
sys_creat_calldata* data = new sys_creat_calldata;
data->pc = pc;
data->pathname = pathname;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_creat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_link;
void syscalls::register_call_sys_link(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_link.push_back(callback);
}
struct sys_link_calldata : public CallbackData {
target_ulong pc;
syscalls::string oldname;
syscalls::string newname;
};
static Callback_RC sys_link_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_link_calldata* data = dynamic_cast<sys_link_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_link_returned, env,data->pc,data->oldname.get_vaddr(),data->newname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_link_callback(CPUState* env,target_ulong pc,syscalls::string oldname,syscalls::string newname) {
for (auto x: internal_registered_callback_sys_link){
    x(env,pc,oldname,newname);
}
if (0 == ppp_on_sys_link_returned_num_cb) return;
sys_link_calldata* data = new sys_link_calldata;
data->pc = pc;
data->oldname = oldname;
data->newname = newname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_link_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_unlink;
void syscalls::register_call_sys_unlink(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_unlink.push_back(callback);
}
struct sys_unlink_calldata : public CallbackData {
target_ulong pc;
syscalls::string pathname;
};
static Callback_RC sys_unlink_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_unlink_calldata* data = dynamic_cast<sys_unlink_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_unlink_returned, env,data->pc,data->pathname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_unlink_callback(CPUState* env,target_ulong pc,syscalls::string pathname) {
for (auto x: internal_registered_callback_sys_unlink){
    x(env,pc,pathname);
}
if (0 == ppp_on_sys_unlink_returned_num_cb) return;
sys_unlink_calldata* data = new sys_unlink_calldata;
data->pc = pc;
data->pathname = pathname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_unlink_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong, target_ulong)>> internal_registered_callback_execve;
void syscalls::register_call_execve(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong, target_ulong)> callback){
internal_registered_callback_execve.push_back(callback);
}
struct execve_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong argv;
target_ulong envp;
};
static Callback_RC execve_returned(CallbackData* opaque, CPUState* env, target_asid asid){
execve_calldata* data = dynamic_cast<execve_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_execve_returned, env,data->pc,data->filename.get_vaddr(),data->argv,data->envp)
return Callback_RC::NORMAL;
}
void syscalls::call_execve_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong argv,target_ulong envp) {
for (auto x: internal_registered_callback_execve){
    x(env,pc,filename,argv,envp);
}
if (0 == ppp_on_execve_returned_num_cb) return;
execve_calldata* data = new execve_calldata;
data->pc = pc;
data->filename = filename;
data->argv = argv;
data->envp = envp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, execve_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_chdir;
void syscalls::register_call_sys_chdir(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_chdir.push_back(callback);
}
struct sys_chdir_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
};
static Callback_RC sys_chdir_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_chdir_calldata* data = dynamic_cast<sys_chdir_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_chdir_returned, env,data->pc,data->filename.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_chdir_callback(CPUState* env,target_ulong pc,syscalls::string filename) {
for (auto x: internal_registered_callback_sys_chdir){
    x(env,pc,filename);
}
if (0 == ppp_on_sys_chdir_returned_num_cb) return;
sys_chdir_calldata* data = new sys_chdir_calldata;
data->pc = pc;
data->filename = filename;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_chdir_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, uint32_t)>> internal_registered_callback_sys_mknod;
void syscalls::register_call_sys_mknod(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, uint32_t)> callback){
internal_registered_callback_sys_mknod.push_back(callback);
}
struct sys_mknod_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
int32_t mode;
uint32_t dev;
};
static Callback_RC sys_mknod_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mknod_calldata* data = dynamic_cast<sys_mknod_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mknod_returned, env,data->pc,data->filename.get_vaddr(),data->mode,data->dev)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mknod_callback(CPUState* env,target_ulong pc,syscalls::string filename,int32_t mode,uint32_t dev) {
for (auto x: internal_registered_callback_sys_mknod){
    x(env,pc,filename,mode,dev);
}
if (0 == ppp_on_sys_mknod_returned_num_cb) return;
sys_mknod_calldata* data = new sys_mknod_calldata;
data->pc = pc;
data->filename = filename;
data->mode = mode;
data->dev = dev;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mknod_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)>> internal_registered_callback_sys_chmod;
void syscalls::register_call_sys_chmod(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_chmod.push_back(callback);
}
struct sys_chmod_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
uint32_t mode;
};
static Callback_RC sys_chmod_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_chmod_calldata* data = dynamic_cast<sys_chmod_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_chmod_returned, env,data->pc,data->filename.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_chmod_callback(CPUState* env,target_ulong pc,syscalls::string filename,uint32_t mode) {
for (auto x: internal_registered_callback_sys_chmod){
    x(env,pc,filename,mode);
}
if (0 == ppp_on_sys_chmod_returned_num_cb) return;
sys_chmod_calldata* data = new sys_chmod_calldata;
data->pc = pc;
data->filename = filename;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_chmod_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)>> internal_registered_callback_sys_lchown16;
void syscalls::register_call_sys_lchown16(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_lchown16.push_back(callback);
}
struct sys_lchown16_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_lchown16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lchown16_calldata* data = dynamic_cast<sys_lchown16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lchown16_returned, env,data->pc,data->filename.get_vaddr(),data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lchown16_callback(CPUState* env,target_ulong pc,syscalls::string filename,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_lchown16){
    x(env,pc,filename,user,group);
}
if (0 == ppp_on_sys_lchown16_returned_num_cb) return;
sys_lchown16_calldata* data = new sys_lchown16_calldata;
data->pc = pc;
data->filename = filename;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lchown16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_lseek;
void syscalls::register_call_sys_lseek(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_lseek.push_back(callback);
}
struct sys_lseek_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t offset;
uint32_t origin;
};
static Callback_RC sys_lseek_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lseek_calldata* data = dynamic_cast<sys_lseek_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lseek_returned, env,data->pc,data->fd,data->offset,data->origin)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lseek_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t offset,uint32_t origin) {
for (auto x: internal_registered_callback_sys_lseek){
    x(env,pc,fd,offset,origin);
}
if (0 == ppp_on_sys_lseek_returned_num_cb) return;
sys_lseek_calldata* data = new sys_lseek_calldata;
data->pc = pc;
data->fd = fd;
data->offset = offset;
data->origin = origin;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lseek_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getpid;
void syscalls::register_call_sys_getpid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getpid.push_back(callback);
}
struct sys_getpid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getpid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getpid_calldata* data = dynamic_cast<sys_getpid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getpid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getpid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getpid){
    x(env,pc);
}
if (0 == ppp_on_sys_getpid_returned_num_cb) return;
sys_getpid_calldata* data = new sys_getpid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getpid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, syscalls::string, uint32_t, target_ulong)>> internal_registered_callback_sys_mount;
void syscalls::register_call_sys_mount(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, syscalls::string, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_mount.push_back(callback);
}
struct sys_mount_calldata : public CallbackData {
target_ulong pc;
syscalls::string dev_name;
syscalls::string dir_name;
syscalls::string type;
uint32_t flags;
target_ulong data_arg;
};
static Callback_RC sys_mount_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mount_calldata* data = dynamic_cast<sys_mount_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mount_returned, env,data->pc,data->dev_name.get_vaddr(),data->dir_name.get_vaddr(),data->type.get_vaddr(),data->flags,data->data_arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mount_callback(CPUState* env,target_ulong pc,syscalls::string dev_name,syscalls::string dir_name,syscalls::string type,uint32_t flags,target_ulong data_arg) {
for (auto x: internal_registered_callback_sys_mount){
    x(env,pc,dev_name,dir_name,type,flags,data_arg);
}
if (0 == ppp_on_sys_mount_returned_num_cb) return;
sys_mount_calldata* data = new sys_mount_calldata;
data->pc = pc;
data->dev_name = dev_name;
data->dir_name = dir_name;
data->type = type;
data->flags = flags;
data->data_arg = data_arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mount_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setuid16;
void syscalls::register_call_sys_setuid16(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setuid16.push_back(callback);
}
struct sys_setuid16_calldata : public CallbackData {
target_ulong pc;
uint32_t uid;
};
static Callback_RC sys_setuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setuid16_calldata* data = dynamic_cast<sys_setuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setuid16_returned, env,data->pc,data->uid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setuid16_callback(CPUState* env,target_ulong pc,uint32_t uid) {
for (auto x: internal_registered_callback_sys_setuid16){
    x(env,pc,uid);
}
if (0 == ppp_on_sys_setuid16_returned_num_cb) return;
sys_setuid16_calldata* data = new sys_setuid16_calldata;
data->pc = pc;
data->uid = uid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getuid16;
void syscalls::register_call_sys_getuid16(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getuid16.push_back(callback);
}
struct sys_getuid16_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getuid16_calldata* data = dynamic_cast<sys_getuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getuid16_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getuid16_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getuid16){
    x(env,pc);
}
if (0 == ppp_on_sys_getuid16_returned_num_cb) return;
sys_getuid16_calldata* data = new sys_getuid16_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, int32_t)>> internal_registered_callback_sys_ptrace;
void syscalls::register_call_sys_ptrace(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_ptrace.push_back(callback);
}
struct sys_ptrace_calldata : public CallbackData {
target_ulong pc;
int32_t request;
int32_t pid;
int32_t addr;
int32_t data_arg;
};
static Callback_RC sys_ptrace_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ptrace_calldata* data = dynamic_cast<sys_ptrace_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ptrace_returned, env,data->pc,data->request,data->pid,data->addr,data->data_arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ptrace_callback(CPUState* env,target_ulong pc,int32_t request,int32_t pid,int32_t addr,int32_t data_arg) {
for (auto x: internal_registered_callback_sys_ptrace){
    x(env,pc,request,pid,addr,data_arg);
}
if (0 == ppp_on_sys_ptrace_returned_num_cb) return;
sys_ptrace_calldata* data = new sys_ptrace_calldata;
data->pc = pc;
data->request = request;
data->pid = pid;
data->addr = addr;
data->data_arg = data_arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ptrace_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_pause;
void syscalls::register_call_sys_pause(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_pause.push_back(callback);
}
struct sys_pause_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_pause_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pause_calldata* data = dynamic_cast<sys_pause_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pause_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pause_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_pause){
    x(env,pc);
}
if (0 == ppp_on_sys_pause_returned_num_cb) return;
sys_pause_calldata* data = new sys_pause_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pause_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_access;
void syscalls::register_call_sys_access(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_access.push_back(callback);
}
struct sys_access_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
int32_t mode;
};
static Callback_RC sys_access_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_access_calldata* data = dynamic_cast<sys_access_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_access_returned, env,data->pc,data->filename.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_access_callback(CPUState* env,target_ulong pc,syscalls::string filename,int32_t mode) {
for (auto x: internal_registered_callback_sys_access){
    x(env,pc,filename,mode);
}
if (0 == ppp_on_sys_access_returned_num_cb) return;
sys_access_calldata* data = new sys_access_calldata;
data->pc = pc;
data->filename = filename;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_access_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_nice;
void syscalls::register_call_sys_nice(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_nice.push_back(callback);
}
struct sys_nice_calldata : public CallbackData {
target_ulong pc;
int32_t increment;
};
static Callback_RC sys_nice_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_nice_calldata* data = dynamic_cast<sys_nice_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_nice_returned, env,data->pc,data->increment)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_nice_callback(CPUState* env,target_ulong pc,int32_t increment) {
for (auto x: internal_registered_callback_sys_nice){
    x(env,pc,increment);
}
if (0 == ppp_on_sys_nice_returned_num_cb) return;
sys_nice_calldata* data = new sys_nice_calldata;
data->pc = pc;
data->increment = increment;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_nice_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_sync;
void syscalls::register_call_sys_sync(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_sync.push_back(callback);
}
struct sys_sync_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_sync_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sync_calldata* data = dynamic_cast<sys_sync_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sync_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sync_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_sync){
    x(env,pc);
}
if (0 == ppp_on_sys_sync_returned_num_cb) return;
sys_sync_calldata* data = new sys_sync_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sync_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_kill;
void syscalls::register_call_sys_kill(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_kill.push_back(callback);
}
struct sys_kill_calldata : public CallbackData {
target_ulong pc;
int32_t pid;
int32_t sig;
};
static Callback_RC sys_kill_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_kill_calldata* data = dynamic_cast<sys_kill_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_kill_returned, env,data->pc,data->pid,data->sig)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_kill_callback(CPUState* env,target_ulong pc,int32_t pid,int32_t sig) {
for (auto x: internal_registered_callback_sys_kill){
    x(env,pc,pid,sig);
}
if (0 == ppp_on_sys_kill_returned_num_cb) return;
sys_kill_calldata* data = new sys_kill_calldata;
data->pc = pc;
data->pid = pid;
data->sig = sig;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_kill_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_rename;
void syscalls::register_call_sys_rename(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_rename.push_back(callback);
}
struct sys_rename_calldata : public CallbackData {
target_ulong pc;
syscalls::string oldname;
syscalls::string newname;
};
static Callback_RC sys_rename_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rename_calldata* data = dynamic_cast<sys_rename_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rename_returned, env,data->pc,data->oldname.get_vaddr(),data->newname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rename_callback(CPUState* env,target_ulong pc,syscalls::string oldname,syscalls::string newname) {
for (auto x: internal_registered_callback_sys_rename){
    x(env,pc,oldname,newname);
}
if (0 == ppp_on_sys_rename_returned_num_cb) return;
sys_rename_calldata* data = new sys_rename_calldata;
data->pc = pc;
data->oldname = oldname;
data->newname = newname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rename_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_mkdir;
void syscalls::register_call_sys_mkdir(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_mkdir.push_back(callback);
}
struct sys_mkdir_calldata : public CallbackData {
target_ulong pc;
syscalls::string pathname;
int32_t mode;
};
static Callback_RC sys_mkdir_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mkdir_calldata* data = dynamic_cast<sys_mkdir_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mkdir_returned, env,data->pc,data->pathname.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mkdir_callback(CPUState* env,target_ulong pc,syscalls::string pathname,int32_t mode) {
for (auto x: internal_registered_callback_sys_mkdir){
    x(env,pc,pathname,mode);
}
if (0 == ppp_on_sys_mkdir_returned_num_cb) return;
sys_mkdir_calldata* data = new sys_mkdir_calldata;
data->pc = pc;
data->pathname = pathname;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mkdir_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_rmdir;
void syscalls::register_call_sys_rmdir(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_rmdir.push_back(callback);
}
struct sys_rmdir_calldata : public CallbackData {
target_ulong pc;
syscalls::string pathname;
};
static Callback_RC sys_rmdir_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rmdir_calldata* data = dynamic_cast<sys_rmdir_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rmdir_returned, env,data->pc,data->pathname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rmdir_callback(CPUState* env,target_ulong pc,syscalls::string pathname) {
for (auto x: internal_registered_callback_sys_rmdir){
    x(env,pc,pathname);
}
if (0 == ppp_on_sys_rmdir_returned_num_cb) return;
sys_rmdir_calldata* data = new sys_rmdir_calldata;
data->pc = pc;
data->pathname = pathname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rmdir_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_dup;
void syscalls::register_call_sys_dup(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_dup.push_back(callback);
}
struct sys_dup_calldata : public CallbackData {
target_ulong pc;
uint32_t fildes;
};
static Callback_RC sys_dup_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_dup_calldata* data = dynamic_cast<sys_dup_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_dup_returned, env,data->pc,data->fildes)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_dup_callback(CPUState* env,target_ulong pc,uint32_t fildes) {
for (auto x: internal_registered_callback_sys_dup){
    x(env,pc,fildes);
}
if (0 == ppp_on_sys_dup_returned_num_cb) return;
sys_dup_calldata* data = new sys_dup_calldata;
data->pc = pc;
data->fildes = fildes;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_dup_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_pipe;
void syscalls::register_call_sys_pipe(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_pipe.push_back(callback);
}
struct sys_pipe_calldata : public CallbackData {
target_ulong pc;
target_ulong arg0;
};
static Callback_RC sys_pipe_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pipe_calldata* data = dynamic_cast<sys_pipe_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pipe_returned, env,data->pc,data->arg0)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pipe_callback(CPUState* env,target_ulong pc,target_ulong arg0) {
for (auto x: internal_registered_callback_sys_pipe){
    x(env,pc,arg0);
}
if (0 == ppp_on_sys_pipe_returned_num_cb) return;
sys_pipe_calldata* data = new sys_pipe_calldata;
data->pc = pc;
data->arg0 = arg0;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pipe_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_times;
void syscalls::register_call_sys_times(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_times.push_back(callback);
}
struct sys_times_calldata : public CallbackData {
target_ulong pc;
target_ulong tbuf;
};
static Callback_RC sys_times_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_times_calldata* data = dynamic_cast<sys_times_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_times_returned, env,data->pc,data->tbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_times_callback(CPUState* env,target_ulong pc,target_ulong tbuf) {
for (auto x: internal_registered_callback_sys_times){
    x(env,pc,tbuf);
}
if (0 == ppp_on_sys_times_returned_num_cb) return;
sys_times_calldata* data = new sys_times_calldata;
data->pc = pc;
data->tbuf = tbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_times_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_brk;
void syscalls::register_call_sys_brk(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_brk.push_back(callback);
}
struct sys_brk_calldata : public CallbackData {
target_ulong pc;
uint32_t brk;
};
static Callback_RC sys_brk_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_brk_calldata* data = dynamic_cast<sys_brk_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_brk_returned, env,data->pc,data->brk)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_brk_callback(CPUState* env,target_ulong pc,uint32_t brk) {
for (auto x: internal_registered_callback_sys_brk){
    x(env,pc,brk);
}
if (0 == ppp_on_sys_brk_returned_num_cb) return;
sys_brk_calldata* data = new sys_brk_calldata;
data->pc = pc;
data->brk = brk;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_brk_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setgid16;
void syscalls::register_call_sys_setgid16(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setgid16.push_back(callback);
}
struct sys_setgid16_calldata : public CallbackData {
target_ulong pc;
uint32_t gid;
};
static Callback_RC sys_setgid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setgid16_calldata* data = dynamic_cast<sys_setgid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setgid16_returned, env,data->pc,data->gid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setgid16_callback(CPUState* env,target_ulong pc,uint32_t gid) {
for (auto x: internal_registered_callback_sys_setgid16){
    x(env,pc,gid);
}
if (0 == ppp_on_sys_setgid16_returned_num_cb) return;
sys_setgid16_calldata* data = new sys_setgid16_calldata;
data->pc = pc;
data->gid = gid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setgid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getgid16;
void syscalls::register_call_sys_getgid16(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getgid16.push_back(callback);
}
struct sys_getgid16_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getgid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getgid16_calldata* data = dynamic_cast<sys_getgid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getgid16_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getgid16_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getgid16){
    x(env,pc);
}
if (0 == ppp_on_sys_getgid16_returned_num_cb) return;
sys_getgid16_calldata* data = new sys_getgid16_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getgid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_geteuid16;
void syscalls::register_call_sys_geteuid16(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_geteuid16.push_back(callback);
}
struct sys_geteuid16_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_geteuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_geteuid16_calldata* data = dynamic_cast<sys_geteuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_geteuid16_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_geteuid16_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_geteuid16){
    x(env,pc);
}
if (0 == ppp_on_sys_geteuid16_returned_num_cb) return;
sys_geteuid16_calldata* data = new sys_geteuid16_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_geteuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getegid16;
void syscalls::register_call_sys_getegid16(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getegid16.push_back(callback);
}
struct sys_getegid16_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getegid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getegid16_calldata* data = dynamic_cast<sys_getegid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getegid16_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getegid16_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getegid16){
    x(env,pc);
}
if (0 == ppp_on_sys_getegid16_returned_num_cb) return;
sys_getegid16_calldata* data = new sys_getegid16_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getegid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_acct;
void syscalls::register_call_sys_acct(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_acct.push_back(callback);
}
struct sys_acct_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
};
static Callback_RC sys_acct_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_acct_calldata* data = dynamic_cast<sys_acct_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_acct_returned, env,data->pc,data->name.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_acct_callback(CPUState* env,target_ulong pc,syscalls::string name) {
for (auto x: internal_registered_callback_sys_acct){
    x(env,pc,name);
}
if (0 == ppp_on_sys_acct_returned_num_cb) return;
sys_acct_calldata* data = new sys_acct_calldata;
data->pc = pc;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_acct_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_umount;
void syscalls::register_call_sys_umount(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_umount.push_back(callback);
}
struct sys_umount_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
int32_t flags;
};
static Callback_RC sys_umount_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_umount_calldata* data = dynamic_cast<sys_umount_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_umount_returned, env,data->pc,data->name.get_vaddr(),data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_umount_callback(CPUState* env,target_ulong pc,syscalls::string name,int32_t flags) {
for (auto x: internal_registered_callback_sys_umount){
    x(env,pc,name,flags);
}
if (0 == ppp_on_sys_umount_returned_num_cb) return;
sys_umount_calldata* data = new sys_umount_calldata;
data->pc = pc;
data->name = name;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_umount_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_ioctl;
void syscalls::register_call_sys_ioctl(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_ioctl.push_back(callback);
}
struct sys_ioctl_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t cmd;
uint32_t arg;
};
static Callback_RC sys_ioctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ioctl_calldata* data = dynamic_cast<sys_ioctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ioctl_returned, env,data->pc,data->fd,data->cmd,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ioctl_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg) {
for (auto x: internal_registered_callback_sys_ioctl){
    x(env,pc,fd,cmd,arg);
}
if (0 == ppp_on_sys_ioctl_returned_num_cb) return;
sys_ioctl_calldata* data = new sys_ioctl_calldata;
data->pc = pc;
data->fd = fd;
data->cmd = cmd;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ioctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_fcntl;
void syscalls::register_call_sys_fcntl(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_fcntl.push_back(callback);
}
struct sys_fcntl_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t cmd;
uint32_t arg;
};
static Callback_RC sys_fcntl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fcntl_calldata* data = dynamic_cast<sys_fcntl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fcntl_returned, env,data->pc,data->fd,data->cmd,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fcntl_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg) {
for (auto x: internal_registered_callback_sys_fcntl){
    x(env,pc,fd,cmd,arg);
}
if (0 == ppp_on_sys_fcntl_returned_num_cb) return;
sys_fcntl_calldata* data = new sys_fcntl_calldata;
data->pc = pc;
data->fd = fd;
data->cmd = cmd;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fcntl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_setpgid;
void syscalls::register_call_sys_setpgid(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setpgid.push_back(callback);
}
struct sys_setpgid_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
uint32_t pgid;
};
static Callback_RC sys_setpgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setpgid_calldata* data = dynamic_cast<sys_setpgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setpgid_returned, env,data->pc,data->pid,data->pgid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setpgid_callback(CPUState* env,target_ulong pc,uint32_t pid,uint32_t pgid) {
for (auto x: internal_registered_callback_sys_setpgid){
    x(env,pc,pid,pgid);
}
if (0 == ppp_on_sys_setpgid_returned_num_cb) return;
sys_setpgid_calldata* data = new sys_setpgid_calldata;
data->pc = pc;
data->pid = pid;
data->pgid = pgid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setpgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_umask;
void syscalls::register_call_sys_umask(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_umask.push_back(callback);
}
struct sys_umask_calldata : public CallbackData {
target_ulong pc;
int32_t mask;
};
static Callback_RC sys_umask_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_umask_calldata* data = dynamic_cast<sys_umask_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_umask_returned, env,data->pc,data->mask)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_umask_callback(CPUState* env,target_ulong pc,int32_t mask) {
for (auto x: internal_registered_callback_sys_umask){
    x(env,pc,mask);
}
if (0 == ppp_on_sys_umask_returned_num_cb) return;
sys_umask_calldata* data = new sys_umask_calldata;
data->pc = pc;
data->mask = mask;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_umask_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_chroot;
void syscalls::register_call_sys_chroot(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_chroot.push_back(callback);
}
struct sys_chroot_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
};
static Callback_RC sys_chroot_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_chroot_calldata* data = dynamic_cast<sys_chroot_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_chroot_returned, env,data->pc,data->filename.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_chroot_callback(CPUState* env,target_ulong pc,syscalls::string filename) {
for (auto x: internal_registered_callback_sys_chroot){
    x(env,pc,filename);
}
if (0 == ppp_on_sys_chroot_returned_num_cb) return;
sys_chroot_calldata* data = new sys_chroot_calldata;
data->pc = pc;
data->filename = filename;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_chroot_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_ustat;
void syscalls::register_call_sys_ustat(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_ustat.push_back(callback);
}
struct sys_ustat_calldata : public CallbackData {
target_ulong pc;
uint32_t dev;
target_ulong ubuf;
};
static Callback_RC sys_ustat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ustat_calldata* data = dynamic_cast<sys_ustat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ustat_returned, env,data->pc,data->dev,data->ubuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ustat_callback(CPUState* env,target_ulong pc,uint32_t dev,target_ulong ubuf) {
for (auto x: internal_registered_callback_sys_ustat){
    x(env,pc,dev,ubuf);
}
if (0 == ppp_on_sys_ustat_returned_num_cb) return;
sys_ustat_calldata* data = new sys_ustat_calldata;
data->pc = pc;
data->dev = dev;
data->ubuf = ubuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ustat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_dup2;
void syscalls::register_call_sys_dup2(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_dup2.push_back(callback);
}
struct sys_dup2_calldata : public CallbackData {
target_ulong pc;
uint32_t oldfd;
uint32_t newfd;
};
static Callback_RC sys_dup2_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_dup2_calldata* data = dynamic_cast<sys_dup2_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_dup2_returned, env,data->pc,data->oldfd,data->newfd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_dup2_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd) {
for (auto x: internal_registered_callback_sys_dup2){
    x(env,pc,oldfd,newfd);
}
if (0 == ppp_on_sys_dup2_returned_num_cb) return;
sys_dup2_calldata* data = new sys_dup2_calldata;
data->pc = pc;
data->oldfd = oldfd;
data->newfd = newfd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_dup2_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getppid;
void syscalls::register_call_sys_getppid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getppid.push_back(callback);
}
struct sys_getppid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getppid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getppid_calldata* data = dynamic_cast<sys_getppid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getppid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getppid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getppid){
    x(env,pc);
}
if (0 == ppp_on_sys_getppid_returned_num_cb) return;
sys_getppid_calldata* data = new sys_getppid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getppid_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getpgrp;
void syscalls::register_call_sys_getpgrp(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getpgrp.push_back(callback);
}
struct sys_getpgrp_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getpgrp_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getpgrp_calldata* data = dynamic_cast<sys_getpgrp_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getpgrp_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getpgrp_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getpgrp){
    x(env,pc);
}
if (0 == ppp_on_sys_getpgrp_returned_num_cb) return;
sys_getpgrp_calldata* data = new sys_getpgrp_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getpgrp_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_setsid;
void syscalls::register_call_sys_setsid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_setsid.push_back(callback);
}
struct sys_setsid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_setsid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setsid_calldata* data = dynamic_cast<sys_setsid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setsid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setsid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_setsid){
    x(env,pc);
}
if (0 == ppp_on_sys_setsid_returned_num_cb) return;
sys_setsid_calldata* data = new sys_setsid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setsid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sigaction;
void syscalls::register_call_sigaction(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sigaction.push_back(callback);
}
struct sigaction_calldata : public CallbackData {
target_ulong pc;
int32_t sig;
target_ulong act;
target_ulong oact;
};
static Callback_RC sigaction_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sigaction_calldata* data = dynamic_cast<sigaction_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sigaction_returned, env,data->pc,data->sig,data->act,data->oact)
return Callback_RC::NORMAL;
}
void syscalls::call_sigaction_callback(CPUState* env,target_ulong pc,int32_t sig,target_ulong act,target_ulong oact) {
for (auto x: internal_registered_callback_sigaction){
    x(env,pc,sig,act,oact);
}
if (0 == ppp_on_sigaction_returned_num_cb) return;
sigaction_calldata* data = new sigaction_calldata;
data->pc = pc;
data->sig = sig;
data->act = act;
data->oact = oact;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sigaction_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_setreuid16;
void syscalls::register_call_sys_setreuid16(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setreuid16.push_back(callback);
}
struct sys_setreuid16_calldata : public CallbackData {
target_ulong pc;
uint32_t ruid;
uint32_t euid;
};
static Callback_RC sys_setreuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setreuid16_calldata* data = dynamic_cast<sys_setreuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setreuid16_returned, env,data->pc,data->ruid,data->euid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setreuid16_callback(CPUState* env,target_ulong pc,uint32_t ruid,uint32_t euid) {
for (auto x: internal_registered_callback_sys_setreuid16){
    x(env,pc,ruid,euid);
}
if (0 == ppp_on_sys_setreuid16_returned_num_cb) return;
sys_setreuid16_calldata* data = new sys_setreuid16_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setreuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_setregid16;
void syscalls::register_call_sys_setregid16(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setregid16.push_back(callback);
}
struct sys_setregid16_calldata : public CallbackData {
target_ulong pc;
uint32_t rgid;
uint32_t egid;
};
static Callback_RC sys_setregid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setregid16_calldata* data = dynamic_cast<sys_setregid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setregid16_returned, env,data->pc,data->rgid,data->egid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setregid16_callback(CPUState* env,target_ulong pc,uint32_t rgid,uint32_t egid) {
for (auto x: internal_registered_callback_sys_setregid16){
    x(env,pc,rgid,egid);
}
if (0 == ppp_on_sys_setregid16_returned_num_cb) return;
sys_setregid16_calldata* data = new sys_setregid16_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setregid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)>> internal_registered_callback_sigsuspend;
void syscalls::register_call_sigsuspend(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sigsuspend.push_back(callback);
}
struct sigsuspend_calldata : public CallbackData {
target_ulong pc;
int32_t restart;
uint32_t oldmask;
uint32_t mask;
};
static Callback_RC sigsuspend_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sigsuspend_calldata* data = dynamic_cast<sigsuspend_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sigsuspend_returned, env,data->pc,data->restart,data->oldmask,data->mask)
return Callback_RC::NORMAL;
}
void syscalls::call_sigsuspend_callback(CPUState* env,target_ulong pc,int32_t restart,uint32_t oldmask,uint32_t mask) {
for (auto x: internal_registered_callback_sigsuspend){
    x(env,pc,restart,oldmask,mask);
}
if (0 == ppp_on_sigsuspend_returned_num_cb) return;
sigsuspend_calldata* data = new sigsuspend_calldata;
data->pc = pc;
data->restart = restart;
data->oldmask = oldmask;
data->mask = mask;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sigsuspend_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_sigpending;
void syscalls::register_call_sys_sigpending(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_sigpending.push_back(callback);
}
struct sys_sigpending_calldata : public CallbackData {
target_ulong pc;
target_ulong set;
};
static Callback_RC sys_sigpending_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sigpending_calldata* data = dynamic_cast<sys_sigpending_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sigpending_returned, env,data->pc,data->set)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sigpending_callback(CPUState* env,target_ulong pc,target_ulong set) {
for (auto x: internal_registered_callback_sys_sigpending){
    x(env,pc,set);
}
if (0 == ppp_on_sys_sigpending_returned_num_cb) return;
sys_sigpending_calldata* data = new sys_sigpending_calldata;
data->pc = pc;
data->set = set;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sigpending_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_sethostname;
void syscalls::register_call_sys_sethostname(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_sethostname.push_back(callback);
}
struct sys_sethostname_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
int32_t len;
};
static Callback_RC sys_sethostname_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sethostname_calldata* data = dynamic_cast<sys_sethostname_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sethostname_returned, env,data->pc,data->name.get_vaddr(),data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sethostname_callback(CPUState* env,target_ulong pc,syscalls::string name,int32_t len) {
for (auto x: internal_registered_callback_sys_sethostname){
    x(env,pc,name,len);
}
if (0 == ppp_on_sys_sethostname_returned_num_cb) return;
sys_sethostname_calldata* data = new sys_sethostname_calldata;
data->pc = pc;
data->name = name;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sethostname_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_setrlimit;
void syscalls::register_call_sys_setrlimit(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_setrlimit.push_back(callback);
}
struct sys_setrlimit_calldata : public CallbackData {
target_ulong pc;
uint32_t resource;
target_ulong rlim;
};
static Callback_RC sys_setrlimit_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setrlimit_calldata* data = dynamic_cast<sys_setrlimit_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setrlimit_returned, env,data->pc,data->resource,data->rlim)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setrlimit_callback(CPUState* env,target_ulong pc,uint32_t resource,target_ulong rlim) {
for (auto x: internal_registered_callback_sys_setrlimit){
    x(env,pc,resource,rlim);
}
if (0 == ppp_on_sys_setrlimit_returned_num_cb) return;
sys_setrlimit_calldata* data = new sys_setrlimit_calldata;
data->pc = pc;
data->resource = resource;
data->rlim = rlim;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setrlimit_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_getrusage;
void syscalls::register_call_sys_getrusage(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_getrusage.push_back(callback);
}
struct sys_getrusage_calldata : public CallbackData {
target_ulong pc;
int32_t who;
target_ulong ru;
};
static Callback_RC sys_getrusage_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getrusage_calldata* data = dynamic_cast<sys_getrusage_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getrusage_returned, env,data->pc,data->who,data->ru)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getrusage_callback(CPUState* env,target_ulong pc,int32_t who,target_ulong ru) {
for (auto x: internal_registered_callback_sys_getrusage){
    x(env,pc,who,ru);
}
if (0 == ppp_on_sys_getrusage_returned_num_cb) return;
sys_getrusage_calldata* data = new sys_getrusage_calldata;
data->pc = pc;
data->who = who;
data->ru = ru;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getrusage_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_gettimeofday;
void syscalls::register_call_sys_gettimeofday(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_gettimeofday.push_back(callback);
}
struct sys_gettimeofday_calldata : public CallbackData {
target_ulong pc;
target_ulong tv;
target_ulong tz;
};
static Callback_RC sys_gettimeofday_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_gettimeofday_calldata* data = dynamic_cast<sys_gettimeofday_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_gettimeofday_returned, env,data->pc,data->tv,data->tz)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_gettimeofday_callback(CPUState* env,target_ulong pc,target_ulong tv,target_ulong tz) {
for (auto x: internal_registered_callback_sys_gettimeofday){
    x(env,pc,tv,tz);
}
if (0 == ppp_on_sys_gettimeofday_returned_num_cb) return;
sys_gettimeofday_calldata* data = new sys_gettimeofday_calldata;
data->pc = pc;
data->tv = tv;
data->tz = tz;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_gettimeofday_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_settimeofday;
void syscalls::register_call_sys_settimeofday(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_settimeofday.push_back(callback);
}
struct sys_settimeofday_calldata : public CallbackData {
target_ulong pc;
target_ulong tv;
target_ulong tz;
};
static Callback_RC sys_settimeofday_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_settimeofday_calldata* data = dynamic_cast<sys_settimeofday_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_settimeofday_returned, env,data->pc,data->tv,data->tz)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_settimeofday_callback(CPUState* env,target_ulong pc,target_ulong tv,target_ulong tz) {
for (auto x: internal_registered_callback_sys_settimeofday){
    x(env,pc,tv,tz);
}
if (0 == ppp_on_sys_settimeofday_returned_num_cb) return;
sys_settimeofday_calldata* data = new sys_settimeofday_calldata;
data->pc = pc;
data->tv = tv;
data->tz = tz;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_settimeofday_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_getgroups16;
void syscalls::register_call_sys_getgroups16(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_getgroups16.push_back(callback);
}
struct sys_getgroups16_calldata : public CallbackData {
target_ulong pc;
int32_t gidsetsize;
target_ulong grouplist;
};
static Callback_RC sys_getgroups16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getgroups16_calldata* data = dynamic_cast<sys_getgroups16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getgroups16_returned, env,data->pc,data->gidsetsize,data->grouplist)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getgroups16_callback(CPUState* env,target_ulong pc,int32_t gidsetsize,target_ulong grouplist) {
for (auto x: internal_registered_callback_sys_getgroups16){
    x(env,pc,gidsetsize,grouplist);
}
if (0 == ppp_on_sys_getgroups16_returned_num_cb) return;
sys_getgroups16_calldata* data = new sys_getgroups16_calldata;
data->pc = pc;
data->gidsetsize = gidsetsize;
data->grouplist = grouplist;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getgroups16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_setgroups16;
void syscalls::register_call_sys_setgroups16(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_setgroups16.push_back(callback);
}
struct sys_setgroups16_calldata : public CallbackData {
target_ulong pc;
int32_t gidsetsize;
target_ulong grouplist;
};
static Callback_RC sys_setgroups16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setgroups16_calldata* data = dynamic_cast<sys_setgroups16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setgroups16_returned, env,data->pc,data->gidsetsize,data->grouplist)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setgroups16_callback(CPUState* env,target_ulong pc,int32_t gidsetsize,target_ulong grouplist) {
for (auto x: internal_registered_callback_sys_setgroups16){
    x(env,pc,gidsetsize,grouplist);
}
if (0 == ppp_on_sys_setgroups16_returned_num_cb) return;
sys_setgroups16_calldata* data = new sys_setgroups16_calldata;
data->pc = pc;
data->gidsetsize = gidsetsize;
data->grouplist = grouplist;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setgroups16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_symlink;
void syscalls::register_call_sys_symlink(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_symlink.push_back(callback);
}
struct sys_symlink_calldata : public CallbackData {
target_ulong pc;
syscalls::string old;
syscalls::string anew;
};
static Callback_RC sys_symlink_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_symlink_calldata* data = dynamic_cast<sys_symlink_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_symlink_returned, env,data->pc,data->old.get_vaddr(),data->anew.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_symlink_callback(CPUState* env,target_ulong pc,syscalls::string old,syscalls::string anew) {
for (auto x: internal_registered_callback_sys_symlink){
    x(env,pc,old,anew);
}
if (0 == ppp_on_sys_symlink_returned_num_cb) return;
sys_symlink_calldata* data = new sys_symlink_calldata;
data->pc = pc;
data->old = old;
data->anew = anew;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_symlink_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong, int32_t)>> internal_registered_callback_sys_readlink;
void syscalls::register_call_sys_readlink(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong, int32_t)> callback){
internal_registered_callback_sys_readlink.push_back(callback);
}
struct sys_readlink_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
target_ulong buf;
int32_t bufsiz;
};
static Callback_RC sys_readlink_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_readlink_calldata* data = dynamic_cast<sys_readlink_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_readlink_returned, env,data->pc,data->path.get_vaddr(),data->buf,data->bufsiz)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_readlink_callback(CPUState* env,target_ulong pc,syscalls::string path,target_ulong buf,int32_t bufsiz) {
for (auto x: internal_registered_callback_sys_readlink){
    x(env,pc,path,buf,bufsiz);
}
if (0 == ppp_on_sys_readlink_returned_num_cb) return;
sys_readlink_calldata* data = new sys_readlink_calldata;
data->pc = pc;
data->path = path;
data->buf = buf;
data->bufsiz = bufsiz;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_readlink_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_uselib;
void syscalls::register_call_sys_uselib(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_uselib.push_back(callback);
}
struct sys_uselib_calldata : public CallbackData {
target_ulong pc;
syscalls::string library;
};
static Callback_RC sys_uselib_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_uselib_calldata* data = dynamic_cast<sys_uselib_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_uselib_returned, env,data->pc,data->library.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_uselib_callback(CPUState* env,target_ulong pc,syscalls::string library) {
for (auto x: internal_registered_callback_sys_uselib){
    x(env,pc,library);
}
if (0 == ppp_on_sys_uselib_returned_num_cb) return;
sys_uselib_calldata* data = new sys_uselib_calldata;
data->pc = pc;
data->library = library;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_uselib_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_swapon;
void syscalls::register_call_sys_swapon(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_swapon.push_back(callback);
}
struct sys_swapon_calldata : public CallbackData {
target_ulong pc;
syscalls::string specialfile;
int32_t swap_flags;
};
static Callback_RC sys_swapon_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_swapon_calldata* data = dynamic_cast<sys_swapon_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_swapon_returned, env,data->pc,data->specialfile.get_vaddr(),data->swap_flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_swapon_callback(CPUState* env,target_ulong pc,syscalls::string specialfile,int32_t swap_flags) {
for (auto x: internal_registered_callback_sys_swapon){
    x(env,pc,specialfile,swap_flags);
}
if (0 == ppp_on_sys_swapon_returned_num_cb) return;
sys_swapon_calldata* data = new sys_swapon_calldata;
data->pc = pc;
data->specialfile = specialfile;
data->swap_flags = swap_flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_swapon_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_reboot;
void syscalls::register_call_sys_reboot(std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_reboot.push_back(callback);
}
struct sys_reboot_calldata : public CallbackData {
target_ulong pc;
int32_t magic1;
int32_t magic2;
uint32_t cmd;
target_ulong arg;
};
static Callback_RC sys_reboot_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_reboot_calldata* data = dynamic_cast<sys_reboot_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_reboot_returned, env,data->pc,data->magic1,data->magic2,data->cmd,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_reboot_callback(CPUState* env,target_ulong pc,int32_t magic1,int32_t magic2,uint32_t cmd,target_ulong arg) {
for (auto x: internal_registered_callback_sys_reboot){
    x(env,pc,magic1,magic2,cmd,arg);
}
if (0 == ppp_on_sys_reboot_returned_num_cb) return;
sys_reboot_calldata* data = new sys_reboot_calldata;
data->pc = pc;
data->magic1 = magic1;
data->magic2 = magic2;
data->cmd = cmd;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_reboot_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_munmap;
void syscalls::register_call_sys_munmap(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_munmap.push_back(callback);
}
struct sys_munmap_calldata : public CallbackData {
target_ulong pc;
uint32_t addr;
uint32_t len;
};
static Callback_RC sys_munmap_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_munmap_calldata* data = dynamic_cast<sys_munmap_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_munmap_returned, env,data->pc,data->addr,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_munmap_callback(CPUState* env,target_ulong pc,uint32_t addr,uint32_t len) {
for (auto x: internal_registered_callback_sys_munmap){
    x(env,pc,addr,len);
}
if (0 == ppp_on_sys_munmap_returned_num_cb) return;
sys_munmap_calldata* data = new sys_munmap_calldata;
data->pc = pc;
data->addr = addr;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_munmap_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)>> internal_registered_callback_sys_truncate;
void syscalls::register_call_sys_truncate(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_truncate.push_back(callback);
}
struct sys_truncate_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
uint32_t length;
};
static Callback_RC sys_truncate_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_truncate_calldata* data = dynamic_cast<sys_truncate_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_truncate_returned, env,data->pc,data->path.get_vaddr(),data->length)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_truncate_callback(CPUState* env,target_ulong pc,syscalls::string path,uint32_t length) {
for (auto x: internal_registered_callback_sys_truncate){
    x(env,pc,path,length);
}
if (0 == ppp_on_sys_truncate_returned_num_cb) return;
sys_truncate_calldata* data = new sys_truncate_calldata;
data->pc = pc;
data->path = path;
data->length = length;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_truncate_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_ftruncate;
void syscalls::register_call_sys_ftruncate(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_ftruncate.push_back(callback);
}
struct sys_ftruncate_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t length;
};
static Callback_RC sys_ftruncate_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ftruncate_calldata* data = dynamic_cast<sys_ftruncate_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ftruncate_returned, env,data->pc,data->fd,data->length)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ftruncate_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t length) {
for (auto x: internal_registered_callback_sys_ftruncate){
    x(env,pc,fd,length);
}
if (0 == ppp_on_sys_ftruncate_returned_num_cb) return;
sys_ftruncate_calldata* data = new sys_ftruncate_calldata;
data->pc = pc;
data->fd = fd;
data->length = length;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ftruncate_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_fchmod;
void syscalls::register_call_sys_fchmod(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_fchmod.push_back(callback);
}
struct sys_fchmod_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t mode;
};
static Callback_RC sys_fchmod_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchmod_calldata* data = dynamic_cast<sys_fchmod_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchmod_returned, env,data->pc,data->fd,data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchmod_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t mode) {
for (auto x: internal_registered_callback_sys_fchmod){
    x(env,pc,fd,mode);
}
if (0 == ppp_on_sys_fchmod_returned_num_cb) return;
sys_fchmod_calldata* data = new sys_fchmod_calldata;
data->pc = pc;
data->fd = fd;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchmod_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_fchown16;
void syscalls::register_call_sys_fchown16(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_fchown16.push_back(callback);
}
struct sys_fchown16_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_fchown16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchown16_calldata* data = dynamic_cast<sys_fchown16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchown16_returned, env,data->pc,data->fd,data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchown16_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_fchown16){
    x(env,pc,fd,user,group);
}
if (0 == ppp_on_sys_fchown16_returned_num_cb) return;
sys_fchown16_calldata* data = new sys_fchown16_calldata;
data->pc = pc;
data->fd = fd;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchown16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_getpriority;
void syscalls::register_call_sys_getpriority(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_getpriority.push_back(callback);
}
struct sys_getpriority_calldata : public CallbackData {
target_ulong pc;
int32_t which;
int32_t who;
};
static Callback_RC sys_getpriority_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getpriority_calldata* data = dynamic_cast<sys_getpriority_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getpriority_returned, env,data->pc,data->which,data->who)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getpriority_callback(CPUState* env,target_ulong pc,int32_t which,int32_t who) {
for (auto x: internal_registered_callback_sys_getpriority){
    x(env,pc,which,who);
}
if (0 == ppp_on_sys_getpriority_returned_num_cb) return;
sys_getpriority_calldata* data = new sys_getpriority_calldata;
data->pc = pc;
data->which = which;
data->who = who;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getpriority_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)>> internal_registered_callback_sys_setpriority;
void syscalls::register_call_sys_setpriority(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_setpriority.push_back(callback);
}
struct sys_setpriority_calldata : public CallbackData {
target_ulong pc;
int32_t which;
int32_t who;
int32_t niceval;
};
static Callback_RC sys_setpriority_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setpriority_calldata* data = dynamic_cast<sys_setpriority_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setpriority_returned, env,data->pc,data->which,data->who,data->niceval)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setpriority_callback(CPUState* env,target_ulong pc,int32_t which,int32_t who,int32_t niceval) {
for (auto x: internal_registered_callback_sys_setpriority){
    x(env,pc,which,who,niceval);
}
if (0 == ppp_on_sys_setpriority_returned_num_cb) return;
sys_setpriority_calldata* data = new sys_setpriority_calldata;
data->pc = pc;
data->which = which;
data->who = who;
data->niceval = niceval;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setpriority_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_statfs;
void syscalls::register_call_sys_statfs(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_statfs.push_back(callback);
}
struct sys_statfs_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
target_ulong buf;
};
static Callback_RC sys_statfs_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_statfs_calldata* data = dynamic_cast<sys_statfs_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_statfs_returned, env,data->pc,data->path.get_vaddr(),data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_statfs_callback(CPUState* env,target_ulong pc,syscalls::string path,target_ulong buf) {
for (auto x: internal_registered_callback_sys_statfs){
    x(env,pc,path,buf);
}
if (0 == ppp_on_sys_statfs_returned_num_cb) return;
sys_statfs_calldata* data = new sys_statfs_calldata;
data->pc = pc;
data->path = path;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_statfs_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_fstatfs;
void syscalls::register_call_sys_fstatfs(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_fstatfs.push_back(callback);
}
struct sys_fstatfs_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong buf;
};
static Callback_RC sys_fstatfs_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fstatfs_calldata* data = dynamic_cast<sys_fstatfs_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fstatfs_returned, env,data->pc,data->fd,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fstatfs_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf) {
for (auto x: internal_registered_callback_sys_fstatfs){
    x(env,pc,fd,buf);
}
if (0 == ppp_on_sys_fstatfs_returned_num_cb) return;
sys_fstatfs_calldata* data = new sys_fstatfs_calldata;
data->pc = pc;
data->fd = fd;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fstatfs_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)>> internal_registered_callback_sys_syslog;
void syscalls::register_call_sys_syslog(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)> callback){
internal_registered_callback_sys_syslog.push_back(callback);
}
struct sys_syslog_calldata : public CallbackData {
target_ulong pc;
int32_t type;
target_ulong buf;
int32_t len;
};
static Callback_RC sys_syslog_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_syslog_calldata* data = dynamic_cast<sys_syslog_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_syslog_returned, env,data->pc,data->type,data->buf,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_syslog_callback(CPUState* env,target_ulong pc,int32_t type,target_ulong buf,int32_t len) {
for (auto x: internal_registered_callback_sys_syslog){
    x(env,pc,type,buf,len);
}
if (0 == ppp_on_sys_syslog_returned_num_cb) return;
sys_syslog_calldata* data = new sys_syslog_calldata;
data->pc = pc;
data->type = type;
data->buf = buf;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_syslog_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_setitimer;
void syscalls::register_call_sys_setitimer(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_setitimer.push_back(callback);
}
struct sys_setitimer_calldata : public CallbackData {
target_ulong pc;
int32_t which;
target_ulong value;
target_ulong ovalue;
};
static Callback_RC sys_setitimer_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setitimer_calldata* data = dynamic_cast<sys_setitimer_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setitimer_returned, env,data->pc,data->which,data->value,data->ovalue)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setitimer_callback(CPUState* env,target_ulong pc,int32_t which,target_ulong value,target_ulong ovalue) {
for (auto x: internal_registered_callback_sys_setitimer){
    x(env,pc,which,value,ovalue);
}
if (0 == ppp_on_sys_setitimer_returned_num_cb) return;
sys_setitimer_calldata* data = new sys_setitimer_calldata;
data->pc = pc;
data->which = which;
data->value = value;
data->ovalue = ovalue;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setitimer_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_getitimer;
void syscalls::register_call_sys_getitimer(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_getitimer.push_back(callback);
}
struct sys_getitimer_calldata : public CallbackData {
target_ulong pc;
int32_t which;
target_ulong value;
};
static Callback_RC sys_getitimer_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getitimer_calldata* data = dynamic_cast<sys_getitimer_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getitimer_returned, env,data->pc,data->which,data->value)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getitimer_callback(CPUState* env,target_ulong pc,int32_t which,target_ulong value) {
for (auto x: internal_registered_callback_sys_getitimer){
    x(env,pc,which,value);
}
if (0 == ppp_on_sys_getitimer_returned_num_cb) return;
sys_getitimer_calldata* data = new sys_getitimer_calldata;
data->pc = pc;
data->which = which;
data->value = value;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getitimer_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_newstat;
void syscalls::register_call_sys_newstat(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_newstat.push_back(callback);
}
struct sys_newstat_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong statbuf;
};
static Callback_RC sys_newstat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_newstat_calldata* data = dynamic_cast<sys_newstat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_newstat_returned, env,data->pc,data->filename.get_vaddr(),data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_newstat_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_newstat){
    x(env,pc,filename,statbuf);
}
if (0 == ppp_on_sys_newstat_returned_num_cb) return;
sys_newstat_calldata* data = new sys_newstat_calldata;
data->pc = pc;
data->filename = filename;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_newstat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_newlstat;
void syscalls::register_call_sys_newlstat(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_newlstat.push_back(callback);
}
struct sys_newlstat_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong statbuf;
};
static Callback_RC sys_newlstat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_newlstat_calldata* data = dynamic_cast<sys_newlstat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_newlstat_returned, env,data->pc,data->filename.get_vaddr(),data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_newlstat_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_newlstat){
    x(env,pc,filename,statbuf);
}
if (0 == ppp_on_sys_newlstat_returned_num_cb) return;
sys_newlstat_calldata* data = new sys_newlstat_calldata;
data->pc = pc;
data->filename = filename;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_newlstat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_newfstat;
void syscalls::register_call_sys_newfstat(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_newfstat.push_back(callback);
}
struct sys_newfstat_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong statbuf;
};
static Callback_RC sys_newfstat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_newfstat_calldata* data = dynamic_cast<sys_newfstat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_newfstat_returned, env,data->pc,data->fd,data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_newfstat_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_newfstat){
    x(env,pc,fd,statbuf);
}
if (0 == ppp_on_sys_newfstat_returned_num_cb) return;
sys_newfstat_calldata* data = new sys_newfstat_calldata;
data->pc = pc;
data->fd = fd;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_newfstat_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_vhangup;
void syscalls::register_call_sys_vhangup(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_vhangup.push_back(callback);
}
struct sys_vhangup_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_vhangup_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_vhangup_calldata* data = dynamic_cast<sys_vhangup_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_vhangup_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_vhangup_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_vhangup){
    x(env,pc);
}
if (0 == ppp_on_sys_vhangup_returned_num_cb) return;
sys_vhangup_calldata* data = new sys_vhangup_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_vhangup_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_wait4;
void syscalls::register_call_sys_wait4(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_wait4.push_back(callback);
}
struct sys_wait4_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
target_ulong stat_addr;
int32_t options;
target_ulong ru;
};
static Callback_RC sys_wait4_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_wait4_calldata* data = dynamic_cast<sys_wait4_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_wait4_returned, env,data->pc,data->pid,data->stat_addr,data->options,data->ru)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_wait4_callback(CPUState* env,target_ulong pc,uint32_t pid,target_ulong stat_addr,int32_t options,target_ulong ru) {
for (auto x: internal_registered_callback_sys_wait4){
    x(env,pc,pid,stat_addr,options,ru);
}
if (0 == ppp_on_sys_wait4_returned_num_cb) return;
sys_wait4_calldata* data = new sys_wait4_calldata;
data->pc = pc;
data->pid = pid;
data->stat_addr = stat_addr;
data->options = options;
data->ru = ru;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_wait4_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_swapoff;
void syscalls::register_call_sys_swapoff(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_swapoff.push_back(callback);
}
struct sys_swapoff_calldata : public CallbackData {
target_ulong pc;
syscalls::string specialfile;
};
static Callback_RC sys_swapoff_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_swapoff_calldata* data = dynamic_cast<sys_swapoff_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_swapoff_returned, env,data->pc,data->specialfile.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_swapoff_callback(CPUState* env,target_ulong pc,syscalls::string specialfile) {
for (auto x: internal_registered_callback_sys_swapoff){
    x(env,pc,specialfile);
}
if (0 == ppp_on_sys_swapoff_returned_num_cb) return;
sys_swapoff_calldata* data = new sys_swapoff_calldata;
data->pc = pc;
data->specialfile = specialfile;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_swapoff_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_sysinfo;
void syscalls::register_call_sys_sysinfo(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_sysinfo.push_back(callback);
}
struct sys_sysinfo_calldata : public CallbackData {
target_ulong pc;
target_ulong info;
};
static Callback_RC sys_sysinfo_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sysinfo_calldata* data = dynamic_cast<sys_sysinfo_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sysinfo_returned, env,data->pc,data->info)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sysinfo_callback(CPUState* env,target_ulong pc,target_ulong info) {
for (auto x: internal_registered_callback_sys_sysinfo){
    x(env,pc,info);
}
if (0 == ppp_on_sys_sysinfo_returned_num_cb) return;
sys_sysinfo_calldata* data = new sys_sysinfo_calldata;
data->pc = pc;
data->info = info;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sysinfo_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_fsync;
void syscalls::register_call_sys_fsync(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_fsync.push_back(callback);
}
struct sys_fsync_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
};
static Callback_RC sys_fsync_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fsync_calldata* data = dynamic_cast<sys_fsync_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fsync_returned, env,data->pc,data->fd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fsync_callback(CPUState* env,target_ulong pc,uint32_t fd) {
for (auto x: internal_registered_callback_sys_fsync){
    x(env,pc,fd);
}
if (0 == ppp_on_sys_fsync_returned_num_cb) return;
sys_fsync_calldata* data = new sys_fsync_calldata;
data->pc = pc;
data->fd = fd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fsync_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sigreturn;
void syscalls::register_call_sigreturn(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sigreturn.push_back(callback);
}
struct sigreturn_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sigreturn_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sigreturn_calldata* data = dynamic_cast<sigreturn_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sigreturn_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sigreturn_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sigreturn){
    x(env,pc);
}
if (0 == ppp_on_sigreturn_returned_num_cb) return;
sigreturn_calldata* data = new sigreturn_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sigreturn_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_clone;
void syscalls::register_call_clone(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_clone.push_back(callback);
}
struct clone_calldata : public CallbackData {
target_ulong pc;
uint32_t clone_flags;
uint32_t newsp;
target_ulong parent_tidptr;
int32_t tls_val;
target_ulong child_tidptr;
target_ulong regs;
};
static Callback_RC clone_returned(CallbackData* opaque, CPUState* env, target_asid asid){
clone_calldata* data = dynamic_cast<clone_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_clone_returned, env,data->pc,data->clone_flags,data->newsp,data->parent_tidptr,data->tls_val,data->child_tidptr,data->regs)
return Callback_RC::NORMAL;
}
void syscalls::call_clone_callback(CPUState* env,target_ulong pc,uint32_t clone_flags,uint32_t newsp,target_ulong parent_tidptr,int32_t tls_val,target_ulong child_tidptr,target_ulong regs) {
for (auto x: internal_registered_callback_clone){
    x(env,pc,clone_flags,newsp,parent_tidptr,tls_val,child_tidptr,regs);
}
if (0 == ppp_on_clone_returned_num_cb) return;
clone_calldata* data = new clone_calldata;
data->pc = pc;
data->clone_flags = clone_flags;
data->newsp = newsp;
data->parent_tidptr = parent_tidptr;
data->tls_val = tls_val;
data->child_tidptr = child_tidptr;
data->regs = regs;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, clone_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)>> internal_registered_callback_sys_setdomainname;
void syscalls::register_call_sys_setdomainname(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_setdomainname.push_back(callback);
}
struct sys_setdomainname_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
int32_t len;
};
static Callback_RC sys_setdomainname_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setdomainname_calldata* data = dynamic_cast<sys_setdomainname_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setdomainname_returned, env,data->pc,data->name.get_vaddr(),data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setdomainname_callback(CPUState* env,target_ulong pc,syscalls::string name,int32_t len) {
for (auto x: internal_registered_callback_sys_setdomainname){
    x(env,pc,name,len);
}
if (0 == ppp_on_sys_setdomainname_returned_num_cb) return;
sys_setdomainname_calldata* data = new sys_setdomainname_calldata;
data->pc = pc;
data->name = name;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setdomainname_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_newuname;
void syscalls::register_call_sys_newuname(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_newuname.push_back(callback);
}
struct sys_newuname_calldata : public CallbackData {
target_ulong pc;
target_ulong name;
};
static Callback_RC sys_newuname_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_newuname_calldata* data = dynamic_cast<sys_newuname_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_newuname_returned, env,data->pc,data->name)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_newuname_callback(CPUState* env,target_ulong pc,target_ulong name) {
for (auto x: internal_registered_callback_sys_newuname){
    x(env,pc,name);
}
if (0 == ppp_on_sys_newuname_returned_num_cb) return;
sys_newuname_calldata* data = new sys_newuname_calldata;
data->pc = pc;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_newuname_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_adjtimex;
void syscalls::register_call_sys_adjtimex(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_adjtimex.push_back(callback);
}
struct sys_adjtimex_calldata : public CallbackData {
target_ulong pc;
target_ulong txc_p;
};
static Callback_RC sys_adjtimex_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_adjtimex_calldata* data = dynamic_cast<sys_adjtimex_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_adjtimex_returned, env,data->pc,data->txc_p)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_adjtimex_callback(CPUState* env,target_ulong pc,target_ulong txc_p) {
for (auto x: internal_registered_callback_sys_adjtimex){
    x(env,pc,txc_p);
}
if (0 == ppp_on_sys_adjtimex_returned_num_cb) return;
sys_adjtimex_calldata* data = new sys_adjtimex_calldata;
data->pc = pc;
data->txc_p = txc_p;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_adjtimex_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_mprotect;
void syscalls::register_call_sys_mprotect(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_mprotect.push_back(callback);
}
struct sys_mprotect_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
uint32_t prot;
};
static Callback_RC sys_mprotect_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mprotect_calldata* data = dynamic_cast<sys_mprotect_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mprotect_returned, env,data->pc,data->start,data->len,data->prot)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mprotect_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len,uint32_t prot) {
for (auto x: internal_registered_callback_sys_mprotect){
    x(env,pc,start,len,prot);
}
if (0 == ppp_on_sys_mprotect_returned_num_cb) return;
sys_mprotect_calldata* data = new sys_mprotect_calldata;
data->pc = pc;
data->start = start;
data->len = len;
data->prot = prot;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mprotect_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_sigprocmask;
void syscalls::register_call_sys_sigprocmask(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_sigprocmask.push_back(callback);
}
struct sys_sigprocmask_calldata : public CallbackData {
target_ulong pc;
int32_t how;
target_ulong set;
target_ulong oset;
};
static Callback_RC sys_sigprocmask_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sigprocmask_calldata* data = dynamic_cast<sys_sigprocmask_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sigprocmask_returned, env,data->pc,data->how,data->set,data->oset)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sigprocmask_callback(CPUState* env,target_ulong pc,int32_t how,target_ulong set,target_ulong oset) {
for (auto x: internal_registered_callback_sys_sigprocmask){
    x(env,pc,how,set,oset);
}
if (0 == ppp_on_sys_sigprocmask_returned_num_cb) return;
sys_sigprocmask_calldata* data = new sys_sigprocmask_calldata;
data->pc = pc;
data->how = how;
data->set = set;
data->oset = oset;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sigprocmask_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t, syscalls::string)>> internal_registered_callback_sys_init_module;
void syscalls::register_call_sys_init_module(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t, syscalls::string)> callback){
internal_registered_callback_sys_init_module.push_back(callback);
}
struct sys_init_module_calldata : public CallbackData {
target_ulong pc;
target_ulong umod;
uint32_t len;
syscalls::string uargs;
};
static Callback_RC sys_init_module_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_init_module_calldata* data = dynamic_cast<sys_init_module_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_init_module_returned, env,data->pc,data->umod,data->len,data->uargs.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_init_module_callback(CPUState* env,target_ulong pc,target_ulong umod,uint32_t len,syscalls::string uargs) {
for (auto x: internal_registered_callback_sys_init_module){
    x(env,pc,umod,len,uargs);
}
if (0 == ppp_on_sys_init_module_returned_num_cb) return;
sys_init_module_calldata* data = new sys_init_module_calldata;
data->pc = pc;
data->umod = umod;
data->len = len;
data->uargs = uargs;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_init_module_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)>> internal_registered_callback_sys_delete_module;
void syscalls::register_call_sys_delete_module(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_delete_module.push_back(callback);
}
struct sys_delete_module_calldata : public CallbackData {
target_ulong pc;
syscalls::string name_user;
uint32_t flags;
};
static Callback_RC sys_delete_module_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_delete_module_calldata* data = dynamic_cast<sys_delete_module_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_delete_module_returned, env,data->pc,data->name_user.get_vaddr(),data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_delete_module_callback(CPUState* env,target_ulong pc,syscalls::string name_user,uint32_t flags) {
for (auto x: internal_registered_callback_sys_delete_module){
    x(env,pc,name_user,flags);
}
if (0 == ppp_on_sys_delete_module_returned_num_cb) return;
sys_delete_module_calldata* data = new sys_delete_module_calldata;
data->pc = pc;
data->name_user = name_user;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_delete_module_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, target_ulong)>> internal_registered_callback_sys_quotactl;
void syscalls::register_call_sys_quotactl(std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_quotactl.push_back(callback);
}
struct sys_quotactl_calldata : public CallbackData {
target_ulong pc;
uint32_t cmd;
syscalls::string special;
uint32_t id;
target_ulong addr;
};
static Callback_RC sys_quotactl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_quotactl_calldata* data = dynamic_cast<sys_quotactl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_quotactl_returned, env,data->pc,data->cmd,data->special.get_vaddr(),data->id,data->addr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_quotactl_callback(CPUState* env,target_ulong pc,uint32_t cmd,syscalls::string special,uint32_t id,target_ulong addr) {
for (auto x: internal_registered_callback_sys_quotactl){
    x(env,pc,cmd,special,id,addr);
}
if (0 == ppp_on_sys_quotactl_returned_num_cb) return;
sys_quotactl_calldata* data = new sys_quotactl_calldata;
data->pc = pc;
data->cmd = cmd;
data->special = special;
data->id = id;
data->addr = addr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_quotactl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_getpgid;
void syscalls::register_call_sys_getpgid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getpgid.push_back(callback);
}
struct sys_getpgid_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
};
static Callback_RC sys_getpgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getpgid_calldata* data = dynamic_cast<sys_getpgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getpgid_returned, env,data->pc,data->pid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getpgid_callback(CPUState* env,target_ulong pc,uint32_t pid) {
for (auto x: internal_registered_callback_sys_getpgid){
    x(env,pc,pid);
}
if (0 == ppp_on_sys_getpgid_returned_num_cb) return;
sys_getpgid_calldata* data = new sys_getpgid_calldata;
data->pc = pc;
data->pid = pid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getpgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_fchdir;
void syscalls::register_call_sys_fchdir(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_fchdir.push_back(callback);
}
struct sys_fchdir_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
};
static Callback_RC sys_fchdir_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchdir_calldata* data = dynamic_cast<sys_fchdir_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchdir_returned, env,data->pc,data->fd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchdir_callback(CPUState* env,target_ulong pc,uint32_t fd) {
for (auto x: internal_registered_callback_sys_fchdir){
    x(env,pc,fd);
}
if (0 == ppp_on_sys_fchdir_returned_num_cb) return;
sys_fchdir_calldata* data = new sys_fchdir_calldata;
data->pc = pc;
data->fd = fd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchdir_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_bdflush;
void syscalls::register_call_sys_bdflush(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_bdflush.push_back(callback);
}
struct sys_bdflush_calldata : public CallbackData {
target_ulong pc;
int32_t func;
int32_t data_arg;
};
static Callback_RC sys_bdflush_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_bdflush_calldata* data = dynamic_cast<sys_bdflush_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_bdflush_returned, env,data->pc,data->func,data->data_arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_bdflush_callback(CPUState* env,target_ulong pc,int32_t func,int32_t data_arg) {
for (auto x: internal_registered_callback_sys_bdflush){
    x(env,pc,func,data_arg);
}
if (0 == ppp_on_sys_bdflush_returned_num_cb) return;
sys_bdflush_calldata* data = new sys_bdflush_calldata;
data->pc = pc;
data->func = func;
data->data_arg = data_arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_bdflush_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_sysfs;
void syscalls::register_call_sys_sysfs(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_sysfs.push_back(callback);
}
struct sys_sysfs_calldata : public CallbackData {
target_ulong pc;
int32_t option;
uint32_t arg1;
uint32_t arg2;
};
static Callback_RC sys_sysfs_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sysfs_calldata* data = dynamic_cast<sys_sysfs_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sysfs_returned, env,data->pc,data->option,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sysfs_callback(CPUState* env,target_ulong pc,int32_t option,uint32_t arg1,uint32_t arg2) {
for (auto x: internal_registered_callback_sys_sysfs){
    x(env,pc,option,arg1,arg2);
}
if (0 == ppp_on_sys_sysfs_returned_num_cb) return;
sys_sysfs_calldata* data = new sys_sysfs_calldata;
data->pc = pc;
data->option = option;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sysfs_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_personality;
void syscalls::register_call_sys_personality(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_personality.push_back(callback);
}
struct sys_personality_calldata : public CallbackData {
target_ulong pc;
int32_t personality;
};
static Callback_RC sys_personality_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_personality_calldata* data = dynamic_cast<sys_personality_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_personality_returned, env,data->pc,data->personality)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_personality_callback(CPUState* env,target_ulong pc,int32_t personality) {
for (auto x: internal_registered_callback_sys_personality){
    x(env,pc,personality);
}
if (0 == ppp_on_sys_personality_returned_num_cb) return;
sys_personality_calldata* data = new sys_personality_calldata;
data->pc = pc;
data->personality = personality;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_personality_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setfsuid16;
void syscalls::register_call_sys_setfsuid16(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setfsuid16.push_back(callback);
}
struct sys_setfsuid16_calldata : public CallbackData {
target_ulong pc;
uint32_t uid;
};
static Callback_RC sys_setfsuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setfsuid16_calldata* data = dynamic_cast<sys_setfsuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setfsuid16_returned, env,data->pc,data->uid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setfsuid16_callback(CPUState* env,target_ulong pc,uint32_t uid) {
for (auto x: internal_registered_callback_sys_setfsuid16){
    x(env,pc,uid);
}
if (0 == ppp_on_sys_setfsuid16_returned_num_cb) return;
sys_setfsuid16_calldata* data = new sys_setfsuid16_calldata;
data->pc = pc;
data->uid = uid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setfsuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setfsgid16;
void syscalls::register_call_sys_setfsgid16(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setfsgid16.push_back(callback);
}
struct sys_setfsgid16_calldata : public CallbackData {
target_ulong pc;
uint32_t gid;
};
static Callback_RC sys_setfsgid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setfsgid16_calldata* data = dynamic_cast<sys_setfsgid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setfsgid16_returned, env,data->pc,data->gid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setfsgid16_callback(CPUState* env,target_ulong pc,uint32_t gid) {
for (auto x: internal_registered_callback_sys_setfsgid16){
    x(env,pc,gid);
}
if (0 == ppp_on_sys_setfsgid16_returned_num_cb) return;
sys_setfsgid16_calldata* data = new sys_setfsgid16_calldata;
data->pc = pc;
data->gid = gid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setfsgid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_llseek;
void syscalls::register_call_sys_llseek(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_llseek.push_back(callback);
}
struct sys_llseek_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t offset_high;
uint32_t offset_low;
target_ulong result;
uint32_t origin;
};
static Callback_RC sys_llseek_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_llseek_calldata* data = dynamic_cast<sys_llseek_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_llseek_returned, env,data->pc,data->fd,data->offset_high,data->offset_low,data->result,data->origin)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_llseek_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t offset_high,uint32_t offset_low,target_ulong result,uint32_t origin) {
for (auto x: internal_registered_callback_sys_llseek){
    x(env,pc,fd,offset_high,offset_low,result,origin);
}
if (0 == ppp_on_sys_llseek_returned_num_cb) return;
sys_llseek_calldata* data = new sys_llseek_calldata;
data->pc = pc;
data->fd = fd;
data->offset_high = offset_high;
data->offset_low = offset_low;
data->result = result;
data->origin = origin;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_llseek_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_getdents;
void syscalls::register_call_sys_getdents(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getdents.push_back(callback);
}
struct sys_getdents_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong dirent;
uint32_t count;
};
static Callback_RC sys_getdents_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getdents_calldata* data = dynamic_cast<sys_getdents_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getdents_returned, env,data->pc,data->fd,data->dirent,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getdents_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong dirent,uint32_t count) {
for (auto x: internal_registered_callback_sys_getdents){
    x(env,pc,fd,dirent,count);
}
if (0 == ppp_on_sys_getdents_returned_num_cb) return;
sys_getdents_calldata* data = new sys_getdents_calldata;
data->pc = pc;
data->fd = fd;
data->dirent = dirent;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getdents_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_select;
void syscalls::register_call_sys_select(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_select.push_back(callback);
}
struct sys_select_calldata : public CallbackData {
target_ulong pc;
int32_t n;
target_ulong inp;
target_ulong outp;
target_ulong exp;
target_ulong tvp;
};
static Callback_RC sys_select_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_select_calldata* data = dynamic_cast<sys_select_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_select_returned, env,data->pc,data->n,data->inp,data->outp,data->exp,data->tvp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_select_callback(CPUState* env,target_ulong pc,int32_t n,target_ulong inp,target_ulong outp,target_ulong exp,target_ulong tvp) {
for (auto x: internal_registered_callback_sys_select){
    x(env,pc,n,inp,outp,exp,tvp);
}
if (0 == ppp_on_sys_select_returned_num_cb) return;
sys_select_calldata* data = new sys_select_calldata;
data->pc = pc;
data->n = n;
data->inp = inp;
data->outp = outp;
data->exp = exp;
data->tvp = tvp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_select_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_flock;
void syscalls::register_call_sys_flock(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_flock.push_back(callback);
}
struct sys_flock_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t cmd;
};
static Callback_RC sys_flock_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_flock_calldata* data = dynamic_cast<sys_flock_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_flock_returned, env,data->pc,data->fd,data->cmd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_flock_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd) {
for (auto x: internal_registered_callback_sys_flock){
    x(env,pc,fd,cmd);
}
if (0 == ppp_on_sys_flock_returned_num_cb) return;
sys_flock_calldata* data = new sys_flock_calldata;
data->pc = pc;
data->fd = fd;
data->cmd = cmd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_flock_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)>> internal_registered_callback_sys_msync;
void syscalls::register_call_sys_msync(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)> callback){
internal_registered_callback_sys_msync.push_back(callback);
}
struct sys_msync_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
int32_t flags;
};
static Callback_RC sys_msync_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_msync_calldata* data = dynamic_cast<sys_msync_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_msync_returned, env,data->pc,data->start,data->len,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_msync_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len,int32_t flags) {
for (auto x: internal_registered_callback_sys_msync){
    x(env,pc,start,len,flags);
}
if (0 == ppp_on_sys_msync_returned_num_cb) return;
sys_msync_calldata* data = new sys_msync_calldata;
data->pc = pc;
data->start = start;
data->len = len;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_msync_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_readv;
void syscalls::register_call_sys_readv(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_readv.push_back(callback);
}
struct sys_readv_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong vec;
uint32_t vlen;
};
static Callback_RC sys_readv_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_readv_calldata* data = dynamic_cast<sys_readv_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_readv_returned, env,data->pc,data->fd,data->vec,data->vlen)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_readv_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
for (auto x: internal_registered_callback_sys_readv){
    x(env,pc,fd,vec,vlen);
}
if (0 == ppp_on_sys_readv_returned_num_cb) return;
sys_readv_calldata* data = new sys_readv_calldata;
data->pc = pc;
data->fd = fd;
data->vec = vec;
data->vlen = vlen;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_readv_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_writev;
void syscalls::register_call_sys_writev(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_writev.push_back(callback);
}
struct sys_writev_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong vec;
uint32_t vlen;
};
static Callback_RC sys_writev_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_writev_calldata* data = dynamic_cast<sys_writev_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_writev_returned, env,data->pc,data->fd,data->vec,data->vlen)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_writev_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong vec,uint32_t vlen) {
for (auto x: internal_registered_callback_sys_writev){
    x(env,pc,fd,vec,vlen);
}
if (0 == ppp_on_sys_writev_returned_num_cb) return;
sys_writev_calldata* data = new sys_writev_calldata;
data->pc = pc;
data->fd = fd;
data->vec = vec;
data->vlen = vlen;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_writev_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_getsid;
void syscalls::register_call_sys_getsid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getsid.push_back(callback);
}
struct sys_getsid_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
};
static Callback_RC sys_getsid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getsid_calldata* data = dynamic_cast<sys_getsid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getsid_returned, env,data->pc,data->pid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getsid_callback(CPUState* env,target_ulong pc,uint32_t pid) {
for (auto x: internal_registered_callback_sys_getsid){
    x(env,pc,pid);
}
if (0 == ppp_on_sys_getsid_returned_num_cb) return;
sys_getsid_calldata* data = new sys_getsid_calldata;
data->pc = pc;
data->pid = pid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getsid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_fdatasync;
void syscalls::register_call_sys_fdatasync(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_fdatasync.push_back(callback);
}
struct sys_fdatasync_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
};
static Callback_RC sys_fdatasync_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fdatasync_calldata* data = dynamic_cast<sys_fdatasync_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fdatasync_returned, env,data->pc,data->fd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fdatasync_callback(CPUState* env,target_ulong pc,uint32_t fd) {
for (auto x: internal_registered_callback_sys_fdatasync){
    x(env,pc,fd);
}
if (0 == ppp_on_sys_fdatasync_returned_num_cb) return;
sys_fdatasync_calldata* data = new sys_fdatasync_calldata;
data->pc = pc;
data->fd = fd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fdatasync_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_sysctl;
void syscalls::register_call_sys_sysctl(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_sysctl.push_back(callback);
}
struct sys_sysctl_calldata : public CallbackData {
target_ulong pc;
target_ulong args;
};
static Callback_RC sys_sysctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sysctl_calldata* data = dynamic_cast<sys_sysctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sysctl_returned, env,data->pc,data->args)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sysctl_callback(CPUState* env,target_ulong pc,target_ulong args) {
for (auto x: internal_registered_callback_sys_sysctl){
    x(env,pc,args);
}
if (0 == ppp_on_sys_sysctl_returned_num_cb) return;
sys_sysctl_calldata* data = new sys_sysctl_calldata;
data->pc = pc;
data->args = args;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sysctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_mlock;
void syscalls::register_call_sys_mlock(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_mlock.push_back(callback);
}
struct sys_mlock_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
};
static Callback_RC sys_mlock_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mlock_calldata* data = dynamic_cast<sys_mlock_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mlock_returned, env,data->pc,data->start,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mlock_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len) {
for (auto x: internal_registered_callback_sys_mlock){
    x(env,pc,start,len);
}
if (0 == ppp_on_sys_mlock_returned_num_cb) return;
sys_mlock_calldata* data = new sys_mlock_calldata;
data->pc = pc;
data->start = start;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mlock_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_munlock;
void syscalls::register_call_sys_munlock(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_munlock.push_back(callback);
}
struct sys_munlock_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
};
static Callback_RC sys_munlock_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_munlock_calldata* data = dynamic_cast<sys_munlock_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_munlock_returned, env,data->pc,data->start,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_munlock_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len) {
for (auto x: internal_registered_callback_sys_munlock){
    x(env,pc,start,len);
}
if (0 == ppp_on_sys_munlock_returned_num_cb) return;
sys_munlock_calldata* data = new sys_munlock_calldata;
data->pc = pc;
data->start = start;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_munlock_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_mlockall;
void syscalls::register_call_sys_mlockall(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_mlockall.push_back(callback);
}
struct sys_mlockall_calldata : public CallbackData {
target_ulong pc;
int32_t flags;
};
static Callback_RC sys_mlockall_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mlockall_calldata* data = dynamic_cast<sys_mlockall_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mlockall_returned, env,data->pc,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mlockall_callback(CPUState* env,target_ulong pc,int32_t flags) {
for (auto x: internal_registered_callback_sys_mlockall){
    x(env,pc,flags);
}
if (0 == ppp_on_sys_mlockall_returned_num_cb) return;
sys_mlockall_calldata* data = new sys_mlockall_calldata;
data->pc = pc;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mlockall_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_munlockall;
void syscalls::register_call_sys_munlockall(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_munlockall.push_back(callback);
}
struct sys_munlockall_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_munlockall_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_munlockall_calldata* data = dynamic_cast<sys_munlockall_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_munlockall_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_munlockall_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_munlockall){
    x(env,pc);
}
if (0 == ppp_on_sys_munlockall_returned_num_cb) return;
sys_munlockall_calldata* data = new sys_munlockall_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_munlockall_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_sched_setparam;
void syscalls::register_call_sys_sched_setparam(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_setparam.push_back(callback);
}
struct sys_sched_setparam_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
target_ulong param;
};
static Callback_RC sys_sched_setparam_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_setparam_calldata* data = dynamic_cast<sys_sched_setparam_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_setparam_returned, env,data->pc,data->pid,data->param)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_setparam_callback(CPUState* env,target_ulong pc,uint32_t pid,target_ulong param) {
for (auto x: internal_registered_callback_sys_sched_setparam){
    x(env,pc,pid,param);
}
if (0 == ppp_on_sys_sched_setparam_returned_num_cb) return;
sys_sched_setparam_calldata* data = new sys_sched_setparam_calldata;
data->pc = pc;
data->pid = pid;
data->param = param;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_setparam_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_sched_getparam;
void syscalls::register_call_sys_sched_getparam(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_getparam.push_back(callback);
}
struct sys_sched_getparam_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
target_ulong param;
};
static Callback_RC sys_sched_getparam_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_getparam_calldata* data = dynamic_cast<sys_sched_getparam_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_getparam_returned, env,data->pc,data->pid,data->param)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_getparam_callback(CPUState* env,target_ulong pc,uint32_t pid,target_ulong param) {
for (auto x: internal_registered_callback_sys_sched_getparam){
    x(env,pc,pid,param);
}
if (0 == ppp_on_sys_sched_getparam_returned_num_cb) return;
sys_sched_getparam_calldata* data = new sys_sched_getparam_calldata;
data->pc = pc;
data->pid = pid;
data->param = param;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_getparam_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong)>> internal_registered_callback_sys_sched_setscheduler;
void syscalls::register_call_sys_sched_setscheduler(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_setscheduler.push_back(callback);
}
struct sys_sched_setscheduler_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
int32_t policy;
target_ulong param;
};
static Callback_RC sys_sched_setscheduler_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_setscheduler_calldata* data = dynamic_cast<sys_sched_setscheduler_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_setscheduler_returned, env,data->pc,data->pid,data->policy,data->param)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_setscheduler_callback(CPUState* env,target_ulong pc,uint32_t pid,int32_t policy,target_ulong param) {
for (auto x: internal_registered_callback_sys_sched_setscheduler){
    x(env,pc,pid,policy,param);
}
if (0 == ppp_on_sys_sched_setscheduler_returned_num_cb) return;
sys_sched_setscheduler_calldata* data = new sys_sched_setscheduler_calldata;
data->pc = pc;
data->pid = pid;
data->policy = policy;
data->param = param;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_setscheduler_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_sched_getscheduler;
void syscalls::register_call_sys_sched_getscheduler(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_sched_getscheduler.push_back(callback);
}
struct sys_sched_getscheduler_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
};
static Callback_RC sys_sched_getscheduler_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_getscheduler_calldata* data = dynamic_cast<sys_sched_getscheduler_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_getscheduler_returned, env,data->pc,data->pid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_getscheduler_callback(CPUState* env,target_ulong pc,uint32_t pid) {
for (auto x: internal_registered_callback_sys_sched_getscheduler){
    x(env,pc,pid);
}
if (0 == ppp_on_sys_sched_getscheduler_returned_num_cb) return;
sys_sched_getscheduler_calldata* data = new sys_sched_getscheduler_calldata;
data->pc = pc;
data->pid = pid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_getscheduler_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_sched_yield;
void syscalls::register_call_sys_sched_yield(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_sched_yield.push_back(callback);
}
struct sys_sched_yield_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_sched_yield_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_yield_calldata* data = dynamic_cast<sys_sched_yield_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_yield_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_yield_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_sched_yield){
    x(env,pc);
}
if (0 == ppp_on_sys_sched_yield_returned_num_cb) return;
sys_sched_yield_calldata* data = new sys_sched_yield_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_yield_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_sched_get_priority_max;
void syscalls::register_call_sys_sched_get_priority_max(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_sched_get_priority_max.push_back(callback);
}
struct sys_sched_get_priority_max_calldata : public CallbackData {
target_ulong pc;
int32_t policy;
};
static Callback_RC sys_sched_get_priority_max_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_get_priority_max_calldata* data = dynamic_cast<sys_sched_get_priority_max_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_get_priority_max_returned, env,data->pc,data->policy)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_get_priority_max_callback(CPUState* env,target_ulong pc,int32_t policy) {
for (auto x: internal_registered_callback_sys_sched_get_priority_max){
    x(env,pc,policy);
}
if (0 == ppp_on_sys_sched_get_priority_max_returned_num_cb) return;
sys_sched_get_priority_max_calldata* data = new sys_sched_get_priority_max_calldata;
data->pc = pc;
data->policy = policy;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_get_priority_max_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_sched_get_priority_min;
void syscalls::register_call_sys_sched_get_priority_min(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_sched_get_priority_min.push_back(callback);
}
struct sys_sched_get_priority_min_calldata : public CallbackData {
target_ulong pc;
int32_t policy;
};
static Callback_RC sys_sched_get_priority_min_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_get_priority_min_calldata* data = dynamic_cast<sys_sched_get_priority_min_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_get_priority_min_returned, env,data->pc,data->policy)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_get_priority_min_callback(CPUState* env,target_ulong pc,int32_t policy) {
for (auto x: internal_registered_callback_sys_sched_get_priority_min){
    x(env,pc,policy);
}
if (0 == ppp_on_sys_sched_get_priority_min_returned_num_cb) return;
sys_sched_get_priority_min_calldata* data = new sys_sched_get_priority_min_calldata;
data->pc = pc;
data->policy = policy;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_get_priority_min_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_sched_rr_get_interval;
void syscalls::register_call_sys_sched_rr_get_interval(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_rr_get_interval.push_back(callback);
}
struct sys_sched_rr_get_interval_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
target_ulong interval;
};
static Callback_RC sys_sched_rr_get_interval_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_rr_get_interval_calldata* data = dynamic_cast<sys_sched_rr_get_interval_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_rr_get_interval_returned, env,data->pc,data->pid,data->interval)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_rr_get_interval_callback(CPUState* env,target_ulong pc,uint32_t pid,target_ulong interval) {
for (auto x: internal_registered_callback_sys_sched_rr_get_interval){
    x(env,pc,pid,interval);
}
if (0 == ppp_on_sys_sched_rr_get_interval_returned_num_cb) return;
sys_sched_rr_get_interval_calldata* data = new sys_sched_rr_get_interval_calldata;
data->pc = pc;
data->pid = pid;
data->interval = interval;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_rr_get_interval_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_nanosleep;
void syscalls::register_call_sys_nanosleep(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_nanosleep.push_back(callback);
}
struct sys_nanosleep_calldata : public CallbackData {
target_ulong pc;
target_ulong rqtp;
target_ulong rmtp;
};
static Callback_RC sys_nanosleep_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_nanosleep_calldata* data = dynamic_cast<sys_nanosleep_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_nanosleep_returned, env,data->pc,data->rqtp,data->rmtp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_nanosleep_callback(CPUState* env,target_ulong pc,target_ulong rqtp,target_ulong rmtp) {
for (auto x: internal_registered_callback_sys_nanosleep){
    x(env,pc,rqtp,rmtp);
}
if (0 == ppp_on_sys_nanosleep_returned_num_cb) return;
sys_nanosleep_calldata* data = new sys_nanosleep_calldata;
data->pc = pc;
data->rqtp = rqtp;
data->rmtp = rmtp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_nanosleep_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_arm_mremap;
void syscalls::register_call_arm_mremap(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_arm_mremap.push_back(callback);
}
struct arm_mremap_calldata : public CallbackData {
target_ulong pc;
uint32_t addr;
uint32_t old_len;
uint32_t new_len;
uint32_t flags;
uint32_t new_addr;
};
static Callback_RC arm_mremap_returned(CallbackData* opaque, CPUState* env, target_asid asid){
arm_mremap_calldata* data = dynamic_cast<arm_mremap_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_arm_mremap_returned, env,data->pc,data->addr,data->old_len,data->new_len,data->flags,data->new_addr)
return Callback_RC::NORMAL;
}
void syscalls::call_arm_mremap_callback(CPUState* env,target_ulong pc,uint32_t addr,uint32_t old_len,uint32_t new_len,uint32_t flags,uint32_t new_addr) {
for (auto x: internal_registered_callback_arm_mremap){
    x(env,pc,addr,old_len,new_len,flags,new_addr);
}
if (0 == ppp_on_arm_mremap_returned_num_cb) return;
arm_mremap_calldata* data = new arm_mremap_calldata;
data->pc = pc;
data->addr = addr;
data->old_len = old_len;
data->new_len = new_len;
data->flags = flags;
data->new_addr = new_addr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, arm_mremap_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_setresuid16;
void syscalls::register_call_sys_setresuid16(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setresuid16.push_back(callback);
}
struct sys_setresuid16_calldata : public CallbackData {
target_ulong pc;
uint32_t ruid;
uint32_t euid;
uint32_t suid;
};
static Callback_RC sys_setresuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setresuid16_calldata* data = dynamic_cast<sys_setresuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setresuid16_returned, env,data->pc,data->ruid,data->euid,data->suid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setresuid16_callback(CPUState* env,target_ulong pc,uint32_t ruid,uint32_t euid,uint32_t suid) {
for (auto x: internal_registered_callback_sys_setresuid16){
    x(env,pc,ruid,euid,suid);
}
if (0 == ppp_on_sys_setresuid16_returned_num_cb) return;
sys_setresuid16_calldata* data = new sys_setresuid16_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
data->suid = suid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setresuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_getresuid16;
void syscalls::register_call_sys_getresuid16(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getresuid16.push_back(callback);
}
struct sys_getresuid16_calldata : public CallbackData {
target_ulong pc;
target_ulong ruid;
target_ulong euid;
target_ulong suid;
};
static Callback_RC sys_getresuid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getresuid16_calldata* data = dynamic_cast<sys_getresuid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getresuid16_returned, env,data->pc,data->ruid,data->euid,data->suid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getresuid16_callback(CPUState* env,target_ulong pc,target_ulong ruid,target_ulong euid,target_ulong suid) {
for (auto x: internal_registered_callback_sys_getresuid16){
    x(env,pc,ruid,euid,suid);
}
if (0 == ppp_on_sys_getresuid16_returned_num_cb) return;
sys_getresuid16_calldata* data = new sys_getresuid16_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
data->suid = suid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getresuid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_poll;
void syscalls::register_call_sys_poll(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_poll.push_back(callback);
}
struct sys_poll_calldata : public CallbackData {
target_ulong pc;
target_ulong ufds;
uint32_t nfds;
int32_t timeout;
};
static Callback_RC sys_poll_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_poll_calldata* data = dynamic_cast<sys_poll_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_poll_returned, env,data->pc,data->ufds,data->nfds,data->timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_poll_callback(CPUState* env,target_ulong pc,target_ulong ufds,uint32_t nfds,int32_t timeout) {
for (auto x: internal_registered_callback_sys_poll){
    x(env,pc,ufds,nfds,timeout);
}
if (0 == ppp_on_sys_poll_returned_num_cb) return;
sys_poll_calldata* data = new sys_poll_calldata;
data->pc = pc;
data->ufds = ufds;
data->nfds = nfds;
data->timeout = timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_poll_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_nfsservctl;
void syscalls::register_call_sys_nfsservctl(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_nfsservctl.push_back(callback);
}
struct sys_nfsservctl_calldata : public CallbackData {
target_ulong pc;
int32_t cmd;
target_ulong arg;
target_ulong res;
};
static Callback_RC sys_nfsservctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_nfsservctl_calldata* data = dynamic_cast<sys_nfsservctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_nfsservctl_returned, env,data->pc,data->cmd,data->arg,data->res)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_nfsservctl_callback(CPUState* env,target_ulong pc,int32_t cmd,target_ulong arg,target_ulong res) {
for (auto x: internal_registered_callback_sys_nfsservctl){
    x(env,pc,cmd,arg,res);
}
if (0 == ppp_on_sys_nfsservctl_returned_num_cb) return;
sys_nfsservctl_calldata* data = new sys_nfsservctl_calldata;
data->pc = pc;
data->cmd = cmd;
data->arg = arg;
data->res = res;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_nfsservctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_setresgid16;
void syscalls::register_call_sys_setresgid16(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setresgid16.push_back(callback);
}
struct sys_setresgid16_calldata : public CallbackData {
target_ulong pc;
uint32_t rgid;
uint32_t egid;
uint32_t sgid;
};
static Callback_RC sys_setresgid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setresgid16_calldata* data = dynamic_cast<sys_setresgid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setresgid16_returned, env,data->pc,data->rgid,data->egid,data->sgid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setresgid16_callback(CPUState* env,target_ulong pc,uint32_t rgid,uint32_t egid,uint32_t sgid) {
for (auto x: internal_registered_callback_sys_setresgid16){
    x(env,pc,rgid,egid,sgid);
}
if (0 == ppp_on_sys_setresgid16_returned_num_cb) return;
sys_setresgid16_calldata* data = new sys_setresgid16_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
data->sgid = sgid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setresgid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_getresgid16;
void syscalls::register_call_sys_getresgid16(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getresgid16.push_back(callback);
}
struct sys_getresgid16_calldata : public CallbackData {
target_ulong pc;
target_ulong rgid;
target_ulong egid;
target_ulong sgid;
};
static Callback_RC sys_getresgid16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getresgid16_calldata* data = dynamic_cast<sys_getresgid16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getresgid16_returned, env,data->pc,data->rgid,data->egid,data->sgid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getresgid16_callback(CPUState* env,target_ulong pc,target_ulong rgid,target_ulong egid,target_ulong sgid) {
for (auto x: internal_registered_callback_sys_getresgid16){
    x(env,pc,rgid,egid,sgid);
}
if (0 == ppp_on_sys_getresgid16_returned_num_cb) return;
sys_getresgid16_calldata* data = new sys_getresgid16_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
data->sgid = sgid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getresgid16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_prctl;
void syscalls::register_call_sys_prctl(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_prctl.push_back(callback);
}
struct sys_prctl_calldata : public CallbackData {
target_ulong pc;
int32_t option;
uint32_t arg2;
uint32_t arg3;
uint32_t arg4;
uint32_t arg5;
};
static Callback_RC sys_prctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_prctl_calldata* data = dynamic_cast<sys_prctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_prctl_returned, env,data->pc,data->option,data->arg2,data->arg3,data->arg4,data->arg5)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_prctl_callback(CPUState* env,target_ulong pc,int32_t option,uint32_t arg2,uint32_t arg3,uint32_t arg4,uint32_t arg5) {
for (auto x: internal_registered_callback_sys_prctl){
    x(env,pc,option,arg2,arg3,arg4,arg5);
}
if (0 == ppp_on_sys_prctl_returned_num_cb) return;
sys_prctl_calldata* data = new sys_prctl_calldata;
data->pc = pc;
data->option = option;
data->arg2 = arg2;
data->arg3 = arg3;
data->arg4 = arg4;
data->arg5 = arg5;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_prctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_rt_sigaction;
void syscalls::register_call_rt_sigaction(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_rt_sigaction.push_back(callback);
}
struct rt_sigaction_calldata : public CallbackData {
target_ulong pc;
int32_t sig;
target_ulong act;
target_ulong oact;
uint32_t sigsetsize;
};
static Callback_RC rt_sigaction_returned(CallbackData* opaque, CPUState* env, target_asid asid){
rt_sigaction_calldata* data = dynamic_cast<rt_sigaction_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_rt_sigaction_returned, env,data->pc,data->sig,data->act,data->oact,data->sigsetsize)
return Callback_RC::NORMAL;
}
void syscalls::call_rt_sigaction_callback(CPUState* env,target_ulong pc,int32_t sig,target_ulong act,target_ulong oact,uint32_t sigsetsize) {
for (auto x: internal_registered_callback_rt_sigaction){
    x(env,pc,sig,act,oact,sigsetsize);
}
if (0 == ppp_on_rt_sigaction_returned_num_cb) return;
rt_sigaction_calldata* data = new rt_sigaction_calldata;
data->pc = pc;
data->sig = sig;
data->act = act;
data->oact = oact;
data->sigsetsize = sigsetsize;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, rt_sigaction_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_rt_sigprocmask;
void syscalls::register_call_sys_rt_sigprocmask(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_rt_sigprocmask.push_back(callback);
}
struct sys_rt_sigprocmask_calldata : public CallbackData {
target_ulong pc;
int32_t how;
target_ulong set;
target_ulong oset;
uint32_t sigsetsize;
};
static Callback_RC sys_rt_sigprocmask_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rt_sigprocmask_calldata* data = dynamic_cast<sys_rt_sigprocmask_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rt_sigprocmask_returned, env,data->pc,data->how,data->set,data->oset,data->sigsetsize)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rt_sigprocmask_callback(CPUState* env,target_ulong pc,int32_t how,target_ulong set,target_ulong oset,uint32_t sigsetsize) {
for (auto x: internal_registered_callback_sys_rt_sigprocmask){
    x(env,pc,how,set,oset,sigsetsize);
}
if (0 == ppp_on_sys_rt_sigprocmask_returned_num_cb) return;
sys_rt_sigprocmask_calldata* data = new sys_rt_sigprocmask_calldata;
data->pc = pc;
data->how = how;
data->set = set;
data->oset = oset;
data->sigsetsize = sigsetsize;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rt_sigprocmask_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_rt_sigpending;
void syscalls::register_call_sys_rt_sigpending(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_rt_sigpending.push_back(callback);
}
struct sys_rt_sigpending_calldata : public CallbackData {
target_ulong pc;
target_ulong set;
uint32_t sigsetsize;
};
static Callback_RC sys_rt_sigpending_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rt_sigpending_calldata* data = dynamic_cast<sys_rt_sigpending_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rt_sigpending_returned, env,data->pc,data->set,data->sigsetsize)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rt_sigpending_callback(CPUState* env,target_ulong pc,target_ulong set,uint32_t sigsetsize) {
for (auto x: internal_registered_callback_sys_rt_sigpending){
    x(env,pc,set,sigsetsize);
}
if (0 == ppp_on_sys_rt_sigpending_returned_num_cb) return;
sys_rt_sigpending_calldata* data = new sys_rt_sigpending_calldata;
data->pc = pc;
data->set = set;
data->sigsetsize = sigsetsize;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rt_sigpending_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_rt_sigtimedwait;
void syscalls::register_call_sys_rt_sigtimedwait(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_rt_sigtimedwait.push_back(callback);
}
struct sys_rt_sigtimedwait_calldata : public CallbackData {
target_ulong pc;
target_ulong uthese;
target_ulong uinfo;
target_ulong uts;
uint32_t sigsetsize;
};
static Callback_RC sys_rt_sigtimedwait_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rt_sigtimedwait_calldata* data = dynamic_cast<sys_rt_sigtimedwait_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rt_sigtimedwait_returned, env,data->pc,data->uthese,data->uinfo,data->uts,data->sigsetsize)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rt_sigtimedwait_callback(CPUState* env,target_ulong pc,target_ulong uthese,target_ulong uinfo,target_ulong uts,uint32_t sigsetsize) {
for (auto x: internal_registered_callback_sys_rt_sigtimedwait){
    x(env,pc,uthese,uinfo,uts,sigsetsize);
}
if (0 == ppp_on_sys_rt_sigtimedwait_returned_num_cb) return;
sys_rt_sigtimedwait_calldata* data = new sys_rt_sigtimedwait_calldata;
data->pc = pc;
data->uthese = uthese;
data->uinfo = uinfo;
data->uts = uts;
data->sigsetsize = sigsetsize;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rt_sigtimedwait_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)>> internal_registered_callback_sys_rt_sigqueueinfo;
void syscalls::register_call_sys_rt_sigqueueinfo(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_rt_sigqueueinfo.push_back(callback);
}
struct sys_rt_sigqueueinfo_calldata : public CallbackData {
target_ulong pc;
int32_t pid;
int32_t sig;
target_ulong uinfo;
};
static Callback_RC sys_rt_sigqueueinfo_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rt_sigqueueinfo_calldata* data = dynamic_cast<sys_rt_sigqueueinfo_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rt_sigqueueinfo_returned, env,data->pc,data->pid,data->sig,data->uinfo)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rt_sigqueueinfo_callback(CPUState* env,target_ulong pc,int32_t pid,int32_t sig,target_ulong uinfo) {
for (auto x: internal_registered_callback_sys_rt_sigqueueinfo){
    x(env,pc,pid,sig,uinfo);
}
if (0 == ppp_on_sys_rt_sigqueueinfo_returned_num_cb) return;
sys_rt_sigqueueinfo_calldata* data = new sys_rt_sigqueueinfo_calldata;
data->pc = pc;
data->pid = pid;
data->sig = sig;
data->uinfo = uinfo;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rt_sigqueueinfo_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_rt_sigsuspend;
void syscalls::register_call_sys_rt_sigsuspend(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_rt_sigsuspend.push_back(callback);
}
struct sys_rt_sigsuspend_calldata : public CallbackData {
target_ulong pc;
target_ulong unewset;
uint32_t sigsetsize;
};
static Callback_RC sys_rt_sigsuspend_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_rt_sigsuspend_calldata* data = dynamic_cast<sys_rt_sigsuspend_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_rt_sigsuspend_returned, env,data->pc,data->unewset,data->sigsetsize)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_rt_sigsuspend_callback(CPUState* env,target_ulong pc,target_ulong unewset,uint32_t sigsetsize) {
for (auto x: internal_registered_callback_sys_rt_sigsuspend){
    x(env,pc,unewset,sigsetsize);
}
if (0 == ppp_on_sys_rt_sigsuspend_returned_num_cb) return;
sys_rt_sigsuspend_calldata* data = new sys_rt_sigsuspend_calldata;
data->pc = pc;
data->unewset = unewset;
data->sigsetsize = sigsetsize;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_rt_sigsuspend_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t, uint64_t)>> internal_registered_callback_sys_pread64;
void syscalls::register_call_sys_pread64(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t, uint64_t)> callback){
internal_registered_callback_sys_pread64.push_back(callback);
}
struct sys_pread64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong buf;
uint32_t count;
uint64_t pos;
};
static Callback_RC sys_pread64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pread64_calldata* data = dynamic_cast<sys_pread64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pread64_returned, env,data->pc,data->fd,data->buf,data->count,data->pos)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pread64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
for (auto x: internal_registered_callback_sys_pread64){
    x(env,pc,fd,buf,count,pos);
}
if (0 == ppp_on_sys_pread64_returned_num_cb) return;
sys_pread64_calldata* data = new sys_pread64_calldata;
data->pc = pc;
data->fd = fd;
data->buf = buf;
data->count = count;
data->pos = pos;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pread64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t, uint64_t)>> internal_registered_callback_sys_pwrite64;
void syscalls::register_call_sys_pwrite64(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t, uint64_t)> callback){
internal_registered_callback_sys_pwrite64.push_back(callback);
}
struct sys_pwrite64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong buf;
uint32_t count;
uint64_t pos;
};
static Callback_RC sys_pwrite64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pwrite64_calldata* data = dynamic_cast<sys_pwrite64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pwrite64_returned, env,data->pc,data->fd,data->buf,data->count,data->pos)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pwrite64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count,uint64_t pos) {
for (auto x: internal_registered_callback_sys_pwrite64){
    x(env,pc,fd,buf,count,pos);
}
if (0 == ppp_on_sys_pwrite64_returned_num_cb) return;
sys_pwrite64_calldata* data = new sys_pwrite64_calldata;
data->pc = pc;
data->fd = fd;
data->buf = buf;
data->count = count;
data->pos = pos;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pwrite64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)>> internal_registered_callback_sys_chown16;
void syscalls::register_call_sys_chown16(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_chown16.push_back(callback);
}
struct sys_chown16_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_chown16_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_chown16_calldata* data = dynamic_cast<sys_chown16_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_chown16_returned, env,data->pc,data->filename.get_vaddr(),data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_chown16_callback(CPUState* env,target_ulong pc,syscalls::string filename,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_chown16){
    x(env,pc,filename,user,group);
}
if (0 == ppp_on_sys_chown16_returned_num_cb) return;
sys_chown16_calldata* data = new sys_chown16_calldata;
data->pc = pc;
data->filename = filename;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_chown16_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_getcwd;
void syscalls::register_call_sys_getcwd(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getcwd.push_back(callback);
}
struct sys_getcwd_calldata : public CallbackData {
target_ulong pc;
target_ulong buf;
uint32_t size;
};
static Callback_RC sys_getcwd_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getcwd_calldata* data = dynamic_cast<sys_getcwd_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getcwd_returned, env,data->pc,data->buf,data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getcwd_callback(CPUState* env,target_ulong pc,target_ulong buf,uint32_t size) {
for (auto x: internal_registered_callback_sys_getcwd){
    x(env,pc,buf,size);
}
if (0 == ppp_on_sys_getcwd_returned_num_cb) return;
sys_getcwd_calldata* data = new sys_getcwd_calldata;
data->pc = pc;
data->buf = buf;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getcwd_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_capget;
void syscalls::register_call_sys_capget(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_capget.push_back(callback);
}
struct sys_capget_calldata : public CallbackData {
target_ulong pc;
target_ulong header;
target_ulong dataptr;
};
static Callback_RC sys_capget_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_capget_calldata* data = dynamic_cast<sys_capget_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_capget_returned, env,data->pc,data->header,data->dataptr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_capget_callback(CPUState* env,target_ulong pc,target_ulong header,target_ulong dataptr) {
for (auto x: internal_registered_callback_sys_capget){
    x(env,pc,header,dataptr);
}
if (0 == ppp_on_sys_capget_returned_num_cb) return;
sys_capget_calldata* data = new sys_capget_calldata;
data->pc = pc;
data->header = header;
data->dataptr = dataptr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_capget_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_capset;
void syscalls::register_call_sys_capset(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_capset.push_back(callback);
}
struct sys_capset_calldata : public CallbackData {
target_ulong pc;
target_ulong header;
target_ulong data_arg;
};
static Callback_RC sys_capset_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_capset_calldata* data = dynamic_cast<sys_capset_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_capset_returned, env,data->pc,data->header,data->data_arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_capset_callback(CPUState* env,target_ulong pc,target_ulong header,target_ulong data_arg) {
for (auto x: internal_registered_callback_sys_capset){
    x(env,pc,header,data_arg);
}
if (0 == ppp_on_sys_capset_returned_num_cb) return;
sys_capset_calldata* data = new sys_capset_calldata;
data->pc = pc;
data->header = header;
data->data_arg = data_arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_capset_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_do_sigaltstack;
void syscalls::register_call_do_sigaltstack(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_do_sigaltstack.push_back(callback);
}
struct do_sigaltstack_calldata : public CallbackData {
target_ulong pc;
target_ulong uss;
target_ulong uoss;
};
static Callback_RC do_sigaltstack_returned(CallbackData* opaque, CPUState* env, target_asid asid){
do_sigaltstack_calldata* data = dynamic_cast<do_sigaltstack_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_do_sigaltstack_returned, env,data->pc,data->uss,data->uoss)
return Callback_RC::NORMAL;
}
void syscalls::call_do_sigaltstack_callback(CPUState* env,target_ulong pc,target_ulong uss,target_ulong uoss) {
for (auto x: internal_registered_callback_do_sigaltstack){
    x(env,pc,uss,uoss);
}
if (0 == ppp_on_do_sigaltstack_returned_num_cb) return;
do_sigaltstack_calldata* data = new do_sigaltstack_calldata;
data->pc = pc;
data->uss = uss;
data->uoss = uoss;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, do_sigaltstack_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_sendfile;
void syscalls::register_call_sys_sendfile(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_sendfile.push_back(callback);
}
struct sys_sendfile_calldata : public CallbackData {
target_ulong pc;
int32_t out_fd;
int32_t in_fd;
target_ulong offset;
uint32_t count;
};
static Callback_RC sys_sendfile_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sendfile_calldata* data = dynamic_cast<sys_sendfile_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sendfile_returned, env,data->pc,data->out_fd,data->in_fd,data->offset,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sendfile_callback(CPUState* env,target_ulong pc,int32_t out_fd,int32_t in_fd,target_ulong offset,uint32_t count) {
for (auto x: internal_registered_callback_sys_sendfile){
    x(env,pc,out_fd,in_fd,offset,count);
}
if (0 == ppp_on_sys_sendfile_returned_num_cb) return;
sys_sendfile_calldata* data = new sys_sendfile_calldata;
data->pc = pc;
data->out_fd = out_fd;
data->in_fd = in_fd;
data->offset = offset;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sendfile_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_vfork;
void syscalls::register_call_vfork(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_vfork.push_back(callback);
}
struct vfork_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC vfork_returned(CallbackData* opaque, CPUState* env, target_asid asid){
vfork_calldata* data = dynamic_cast<vfork_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_vfork_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_vfork_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_vfork){
    x(env,pc);
}
if (0 == ppp_on_vfork_returned_num_cb) return;
vfork_calldata* data = new vfork_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, vfork_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_getrlimit;
void syscalls::register_call_sys_getrlimit(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_getrlimit.push_back(callback);
}
struct sys_getrlimit_calldata : public CallbackData {
target_ulong pc;
uint32_t resource;
target_ulong rlim;
};
static Callback_RC sys_getrlimit_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getrlimit_calldata* data = dynamic_cast<sys_getrlimit_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getrlimit_returned, env,data->pc,data->resource,data->rlim)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getrlimit_callback(CPUState* env,target_ulong pc,uint32_t resource,target_ulong rlim) {
for (auto x: internal_registered_callback_sys_getrlimit){
    x(env,pc,resource,rlim);
}
if (0 == ppp_on_sys_getrlimit_returned_num_cb) return;
sys_getrlimit_calldata* data = new sys_getrlimit_calldata;
data->pc = pc;
data->resource = resource;
data->rlim = rlim;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getrlimit_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_do_mmap2;
void syscalls::register_call_do_mmap2(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_do_mmap2.push_back(callback);
}
struct do_mmap2_calldata : public CallbackData {
target_ulong pc;
uint32_t addr;
uint32_t len;
uint32_t prot;
uint32_t flags;
uint32_t fd;
uint32_t pgoff;
};
static Callback_RC do_mmap2_returned(CallbackData* opaque, CPUState* env, target_asid asid){
do_mmap2_calldata* data = dynamic_cast<do_mmap2_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_do_mmap2_returned, env,data->pc,data->addr,data->len,data->prot,data->flags,data->fd,data->pgoff)
return Callback_RC::NORMAL;
}
void syscalls::call_do_mmap2_callback(CPUState* env,target_ulong pc,uint32_t addr,uint32_t len,uint32_t prot,uint32_t flags,uint32_t fd,uint32_t pgoff) {
for (auto x: internal_registered_callback_do_mmap2){
    x(env,pc,addr,len,prot,flags,fd,pgoff);
}
if (0 == ppp_on_do_mmap2_returned_num_cb) return;
do_mmap2_calldata* data = new do_mmap2_calldata;
data->pc = pc;
data->addr = addr;
data->len = len;
data->prot = prot;
data->flags = flags;
data->fd = fd;
data->pgoff = pgoff;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, do_mmap2_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint64_t)>> internal_registered_callback_sys_truncate64;
void syscalls::register_call_sys_truncate64(std::function<void(CPUState*, target_ulong, syscalls::string, uint64_t)> callback){
internal_registered_callback_sys_truncate64.push_back(callback);
}
struct sys_truncate64_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
uint64_t length;
};
static Callback_RC sys_truncate64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_truncate64_calldata* data = dynamic_cast<sys_truncate64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_truncate64_returned, env,data->pc,data->path.get_vaddr(),data->length)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_truncate64_callback(CPUState* env,target_ulong pc,syscalls::string path,uint64_t length) {
for (auto x: internal_registered_callback_sys_truncate64){
    x(env,pc,path,length);
}
if (0 == ppp_on_sys_truncate64_returned_num_cb) return;
sys_truncate64_calldata* data = new sys_truncate64_calldata;
data->pc = pc;
data->path = path;
data->length = length;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_truncate64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint64_t)>> internal_registered_callback_sys_ftruncate64;
void syscalls::register_call_sys_ftruncate64(std::function<void(CPUState*, target_ulong, uint32_t, uint64_t)> callback){
internal_registered_callback_sys_ftruncate64.push_back(callback);
}
struct sys_ftruncate64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint64_t length;
};
static Callback_RC sys_ftruncate64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ftruncate64_calldata* data = dynamic_cast<sys_ftruncate64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ftruncate64_returned, env,data->pc,data->fd,data->length)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ftruncate64_callback(CPUState* env,target_ulong pc,uint32_t fd,uint64_t length) {
for (auto x: internal_registered_callback_sys_ftruncate64){
    x(env,pc,fd,length);
}
if (0 == ppp_on_sys_ftruncate64_returned_num_cb) return;
sys_ftruncate64_calldata* data = new sys_ftruncate64_calldata;
data->pc = pc;
data->fd = fd;
data->length = length;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ftruncate64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_stat64;
void syscalls::register_call_sys_stat64(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_stat64.push_back(callback);
}
struct sys_stat64_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong statbuf;
};
static Callback_RC sys_stat64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_stat64_calldata* data = dynamic_cast<sys_stat64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_stat64_returned, env,data->pc,data->filename.get_vaddr(),data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_stat64_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_stat64){
    x(env,pc,filename,statbuf);
}
if (0 == ppp_on_sys_stat64_returned_num_cb) return;
sys_stat64_calldata* data = new sys_stat64_calldata;
data->pc = pc;
data->filename = filename;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_stat64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_lstat64;
void syscalls::register_call_sys_lstat64(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_lstat64.push_back(callback);
}
struct sys_lstat64_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong statbuf;
};
static Callback_RC sys_lstat64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lstat64_calldata* data = dynamic_cast<sys_lstat64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lstat64_returned, env,data->pc,data->filename.get_vaddr(),data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lstat64_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_lstat64){
    x(env,pc,filename,statbuf);
}
if (0 == ppp_on_sys_lstat64_returned_num_cb) return;
sys_lstat64_calldata* data = new sys_lstat64_calldata;
data->pc = pc;
data->filename = filename;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lstat64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_fstat64;
void syscalls::register_call_sys_fstat64(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_fstat64.push_back(callback);
}
struct sys_fstat64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong statbuf;
};
static Callback_RC sys_fstat64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fstat64_calldata* data = dynamic_cast<sys_fstat64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fstat64_returned, env,data->pc,data->fd,data->statbuf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fstat64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong statbuf) {
for (auto x: internal_registered_callback_sys_fstat64){
    x(env,pc,fd,statbuf);
}
if (0 == ppp_on_sys_fstat64_returned_num_cb) return;
sys_fstat64_calldata* data = new sys_fstat64_calldata;
data->pc = pc;
data->fd = fd;
data->statbuf = statbuf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fstat64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)>> internal_registered_callback_sys_lchown;
void syscalls::register_call_sys_lchown(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_lchown.push_back(callback);
}
struct sys_lchown_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_lchown_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lchown_calldata* data = dynamic_cast<sys_lchown_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lchown_returned, env,data->pc,data->filename.get_vaddr(),data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lchown_callback(CPUState* env,target_ulong pc,syscalls::string filename,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_lchown){
    x(env,pc,filename,user,group);
}
if (0 == ppp_on_sys_lchown_returned_num_cb) return;
sys_lchown_calldata* data = new sys_lchown_calldata;
data->pc = pc;
data->filename = filename;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lchown_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getuid;
void syscalls::register_call_sys_getuid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getuid.push_back(callback);
}
struct sys_getuid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getuid_calldata* data = dynamic_cast<sys_getuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getuid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getuid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getuid){
    x(env,pc);
}
if (0 == ppp_on_sys_getuid_returned_num_cb) return;
sys_getuid_calldata* data = new sys_getuid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getgid;
void syscalls::register_call_sys_getgid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getgid.push_back(callback);
}
struct sys_getgid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getgid_calldata* data = dynamic_cast<sys_getgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getgid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getgid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getgid){
    x(env,pc);
}
if (0 == ppp_on_sys_getgid_returned_num_cb) return;
sys_getgid_calldata* data = new sys_getgid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_geteuid;
void syscalls::register_call_sys_geteuid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_geteuid.push_back(callback);
}
struct sys_geteuid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_geteuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_geteuid_calldata* data = dynamic_cast<sys_geteuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_geteuid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_geteuid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_geteuid){
    x(env,pc);
}
if (0 == ppp_on_sys_geteuid_returned_num_cb) return;
sys_geteuid_calldata* data = new sys_geteuid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_geteuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_getegid;
void syscalls::register_call_sys_getegid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_getegid.push_back(callback);
}
struct sys_getegid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_getegid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getegid_calldata* data = dynamic_cast<sys_getegid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getegid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getegid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_getegid){
    x(env,pc);
}
if (0 == ppp_on_sys_getegid_returned_num_cb) return;
sys_getegid_calldata* data = new sys_getegid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getegid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_setreuid;
void syscalls::register_call_sys_setreuid(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setreuid.push_back(callback);
}
struct sys_setreuid_calldata : public CallbackData {
target_ulong pc;
uint32_t ruid;
uint32_t euid;
};
static Callback_RC sys_setreuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setreuid_calldata* data = dynamic_cast<sys_setreuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setreuid_returned, env,data->pc,data->ruid,data->euid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setreuid_callback(CPUState* env,target_ulong pc,uint32_t ruid,uint32_t euid) {
for (auto x: internal_registered_callback_sys_setreuid){
    x(env,pc,ruid,euid);
}
if (0 == ppp_on_sys_setreuid_returned_num_cb) return;
sys_setreuid_calldata* data = new sys_setreuid_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setreuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_setregid;
void syscalls::register_call_sys_setregid(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setregid.push_back(callback);
}
struct sys_setregid_calldata : public CallbackData {
target_ulong pc;
uint32_t rgid;
uint32_t egid;
};
static Callback_RC sys_setregid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setregid_calldata* data = dynamic_cast<sys_setregid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setregid_returned, env,data->pc,data->rgid,data->egid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setregid_callback(CPUState* env,target_ulong pc,uint32_t rgid,uint32_t egid) {
for (auto x: internal_registered_callback_sys_setregid){
    x(env,pc,rgid,egid);
}
if (0 == ppp_on_sys_setregid_returned_num_cb) return;
sys_setregid_calldata* data = new sys_setregid_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setregid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_getgroups;
void syscalls::register_call_sys_getgroups(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_getgroups.push_back(callback);
}
struct sys_getgroups_calldata : public CallbackData {
target_ulong pc;
int32_t gidsetsize;
target_ulong grouplist;
};
static Callback_RC sys_getgroups_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getgroups_calldata* data = dynamic_cast<sys_getgroups_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getgroups_returned, env,data->pc,data->gidsetsize,data->grouplist)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getgroups_callback(CPUState* env,target_ulong pc,int32_t gidsetsize,target_ulong grouplist) {
for (auto x: internal_registered_callback_sys_getgroups){
    x(env,pc,gidsetsize,grouplist);
}
if (0 == ppp_on_sys_getgroups_returned_num_cb) return;
sys_getgroups_calldata* data = new sys_getgroups_calldata;
data->pc = pc;
data->gidsetsize = gidsetsize;
data->grouplist = grouplist;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getgroups_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_setgroups;
void syscalls::register_call_sys_setgroups(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_setgroups.push_back(callback);
}
struct sys_setgroups_calldata : public CallbackData {
target_ulong pc;
int32_t gidsetsize;
target_ulong grouplist;
};
static Callback_RC sys_setgroups_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setgroups_calldata* data = dynamic_cast<sys_setgroups_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setgroups_returned, env,data->pc,data->gidsetsize,data->grouplist)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setgroups_callback(CPUState* env,target_ulong pc,int32_t gidsetsize,target_ulong grouplist) {
for (auto x: internal_registered_callback_sys_setgroups){
    x(env,pc,gidsetsize,grouplist);
}
if (0 == ppp_on_sys_setgroups_returned_num_cb) return;
sys_setgroups_calldata* data = new sys_setgroups_calldata;
data->pc = pc;
data->gidsetsize = gidsetsize;
data->grouplist = grouplist;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setgroups_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_fchown;
void syscalls::register_call_sys_fchown(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_fchown.push_back(callback);
}
struct sys_fchown_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_fchown_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchown_calldata* data = dynamic_cast<sys_fchown_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchown_returned, env,data->pc,data->fd,data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchown_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_fchown){
    x(env,pc,fd,user,group);
}
if (0 == ppp_on_sys_fchown_returned_num_cb) return;
sys_fchown_calldata* data = new sys_fchown_calldata;
data->pc = pc;
data->fd = fd;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchown_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_setresuid;
void syscalls::register_call_sys_setresuid(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setresuid.push_back(callback);
}
struct sys_setresuid_calldata : public CallbackData {
target_ulong pc;
uint32_t ruid;
uint32_t euid;
uint32_t suid;
};
static Callback_RC sys_setresuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setresuid_calldata* data = dynamic_cast<sys_setresuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setresuid_returned, env,data->pc,data->ruid,data->euid,data->suid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setresuid_callback(CPUState* env,target_ulong pc,uint32_t ruid,uint32_t euid,uint32_t suid) {
for (auto x: internal_registered_callback_sys_setresuid){
    x(env,pc,ruid,euid,suid);
}
if (0 == ppp_on_sys_setresuid_returned_num_cb) return;
sys_setresuid_calldata* data = new sys_setresuid_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
data->suid = suid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setresuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_getresuid;
void syscalls::register_call_sys_getresuid(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getresuid.push_back(callback);
}
struct sys_getresuid_calldata : public CallbackData {
target_ulong pc;
target_ulong ruid;
target_ulong euid;
target_ulong suid;
};
static Callback_RC sys_getresuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getresuid_calldata* data = dynamic_cast<sys_getresuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getresuid_returned, env,data->pc,data->ruid,data->euid,data->suid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getresuid_callback(CPUState* env,target_ulong pc,target_ulong ruid,target_ulong euid,target_ulong suid) {
for (auto x: internal_registered_callback_sys_getresuid){
    x(env,pc,ruid,euid,suid);
}
if (0 == ppp_on_sys_getresuid_returned_num_cb) return;
sys_getresuid_calldata* data = new sys_getresuid_calldata;
data->pc = pc;
data->ruid = ruid;
data->euid = euid;
data->suid = suid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getresuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_setresgid;
void syscalls::register_call_sys_setresgid(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_setresgid.push_back(callback);
}
struct sys_setresgid_calldata : public CallbackData {
target_ulong pc;
uint32_t rgid;
uint32_t egid;
uint32_t sgid;
};
static Callback_RC sys_setresgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setresgid_calldata* data = dynamic_cast<sys_setresgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setresgid_returned, env,data->pc,data->rgid,data->egid,data->sgid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setresgid_callback(CPUState* env,target_ulong pc,uint32_t rgid,uint32_t egid,uint32_t sgid) {
for (auto x: internal_registered_callback_sys_setresgid){
    x(env,pc,rgid,egid,sgid);
}
if (0 == ppp_on_sys_setresgid_returned_num_cb) return;
sys_setresgid_calldata* data = new sys_setresgid_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
data->sgid = sgid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setresgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_getresgid;
void syscalls::register_call_sys_getresgid(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getresgid.push_back(callback);
}
struct sys_getresgid_calldata : public CallbackData {
target_ulong pc;
target_ulong rgid;
target_ulong egid;
target_ulong sgid;
};
static Callback_RC sys_getresgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getresgid_calldata* data = dynamic_cast<sys_getresgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getresgid_returned, env,data->pc,data->rgid,data->egid,data->sgid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getresgid_callback(CPUState* env,target_ulong pc,target_ulong rgid,target_ulong egid,target_ulong sgid) {
for (auto x: internal_registered_callback_sys_getresgid){
    x(env,pc,rgid,egid,sgid);
}
if (0 == ppp_on_sys_getresgid_returned_num_cb) return;
sys_getresgid_calldata* data = new sys_getresgid_calldata;
data->pc = pc;
data->rgid = rgid;
data->egid = egid;
data->sgid = sgid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getresgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)>> internal_registered_callback_sys_chown;
void syscalls::register_call_sys_chown(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_chown.push_back(callback);
}
struct sys_chown_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
uint32_t user;
uint32_t group;
};
static Callback_RC sys_chown_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_chown_calldata* data = dynamic_cast<sys_chown_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_chown_returned, env,data->pc,data->filename.get_vaddr(),data->user,data->group)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_chown_callback(CPUState* env,target_ulong pc,syscalls::string filename,uint32_t user,uint32_t group) {
for (auto x: internal_registered_callback_sys_chown){
    x(env,pc,filename,user,group);
}
if (0 == ppp_on_sys_chown_returned_num_cb) return;
sys_chown_calldata* data = new sys_chown_calldata;
data->pc = pc;
data->filename = filename;
data->user = user;
data->group = group;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_chown_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setuid;
void syscalls::register_call_sys_setuid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setuid.push_back(callback);
}
struct sys_setuid_calldata : public CallbackData {
target_ulong pc;
uint32_t uid;
};
static Callback_RC sys_setuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setuid_calldata* data = dynamic_cast<sys_setuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setuid_returned, env,data->pc,data->uid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setuid_callback(CPUState* env,target_ulong pc,uint32_t uid) {
for (auto x: internal_registered_callback_sys_setuid){
    x(env,pc,uid);
}
if (0 == ppp_on_sys_setuid_returned_num_cb) return;
sys_setuid_calldata* data = new sys_setuid_calldata;
data->pc = pc;
data->uid = uid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setgid;
void syscalls::register_call_sys_setgid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setgid.push_back(callback);
}
struct sys_setgid_calldata : public CallbackData {
target_ulong pc;
uint32_t gid;
};
static Callback_RC sys_setgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setgid_calldata* data = dynamic_cast<sys_setgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setgid_returned, env,data->pc,data->gid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setgid_callback(CPUState* env,target_ulong pc,uint32_t gid) {
for (auto x: internal_registered_callback_sys_setgid){
    x(env,pc,gid);
}
if (0 == ppp_on_sys_setgid_returned_num_cb) return;
sys_setgid_calldata* data = new sys_setgid_calldata;
data->pc = pc;
data->gid = gid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setfsuid;
void syscalls::register_call_sys_setfsuid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setfsuid.push_back(callback);
}
struct sys_setfsuid_calldata : public CallbackData {
target_ulong pc;
uint32_t uid;
};
static Callback_RC sys_setfsuid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setfsuid_calldata* data = dynamic_cast<sys_setfsuid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setfsuid_returned, env,data->pc,data->uid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setfsuid_callback(CPUState* env,target_ulong pc,uint32_t uid) {
for (auto x: internal_registered_callback_sys_setfsuid){
    x(env,pc,uid);
}
if (0 == ppp_on_sys_setfsuid_returned_num_cb) return;
sys_setfsuid_calldata* data = new sys_setfsuid_calldata;
data->pc = pc;
data->uid = uid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setfsuid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_setfsgid;
void syscalls::register_call_sys_setfsgid(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_setfsgid.push_back(callback);
}
struct sys_setfsgid_calldata : public CallbackData {
target_ulong pc;
uint32_t gid;
};
static Callback_RC sys_setfsgid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setfsgid_calldata* data = dynamic_cast<sys_setfsgid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setfsgid_returned, env,data->pc,data->gid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setfsgid_callback(CPUState* env,target_ulong pc,uint32_t gid) {
for (auto x: internal_registered_callback_sys_setfsgid){
    x(env,pc,gid);
}
if (0 == ppp_on_sys_setfsgid_returned_num_cb) return;
sys_setfsgid_calldata* data = new sys_setfsgid_calldata;
data->pc = pc;
data->gid = gid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setfsgid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_getdents64;
void syscalls::register_call_sys_getdents64(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getdents64.push_back(callback);
}
struct sys_getdents64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
target_ulong dirent;
uint32_t count;
};
static Callback_RC sys_getdents64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getdents64_calldata* data = dynamic_cast<sys_getdents64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getdents64_returned, env,data->pc,data->fd,data->dirent,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getdents64_callback(CPUState* env,target_ulong pc,uint32_t fd,target_ulong dirent,uint32_t count) {
for (auto x: internal_registered_callback_sys_getdents64){
    x(env,pc,fd,dirent,count);
}
if (0 == ppp_on_sys_getdents64_returned_num_cb) return;
sys_getdents64_calldata* data = new sys_getdents64_calldata;
data->pc = pc;
data->fd = fd;
data->dirent = dirent;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getdents64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_pivot_root;
void syscalls::register_call_sys_pivot_root(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_pivot_root.push_back(callback);
}
struct sys_pivot_root_calldata : public CallbackData {
target_ulong pc;
syscalls::string new_root;
syscalls::string put_old;
};
static Callback_RC sys_pivot_root_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pivot_root_calldata* data = dynamic_cast<sys_pivot_root_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pivot_root_returned, env,data->pc,data->new_root.get_vaddr(),data->put_old.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pivot_root_callback(CPUState* env,target_ulong pc,syscalls::string new_root,syscalls::string put_old) {
for (auto x: internal_registered_callback_sys_pivot_root){
    x(env,pc,new_root,put_old);
}
if (0 == ppp_on_sys_pivot_root_returned_num_cb) return;
sys_pivot_root_calldata* data = new sys_pivot_root_calldata;
data->pc = pc;
data->new_root = new_root;
data->put_old = put_old;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pivot_root_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, syscalls::string)>> internal_registered_callback_sys_mincore;
void syscalls::register_call_sys_mincore(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, syscalls::string)> callback){
internal_registered_callback_sys_mincore.push_back(callback);
}
struct sys_mincore_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
syscalls::string vec;
};
static Callback_RC sys_mincore_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mincore_calldata* data = dynamic_cast<sys_mincore_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mincore_returned, env,data->pc,data->start,data->len,data->vec.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mincore_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len,syscalls::string vec) {
for (auto x: internal_registered_callback_sys_mincore){
    x(env,pc,start,len,vec);
}
if (0 == ppp_on_sys_mincore_returned_num_cb) return;
sys_mincore_calldata* data = new sys_mincore_calldata;
data->pc = pc;
data->start = start;
data->len = len;
data->vec = vec;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mincore_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)>> internal_registered_callback_sys_madvise;
void syscalls::register_call_sys_madvise(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)> callback){
internal_registered_callback_sys_madvise.push_back(callback);
}
struct sys_madvise_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
int32_t behavior;
};
static Callback_RC sys_madvise_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_madvise_calldata* data = dynamic_cast<sys_madvise_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_madvise_returned, env,data->pc,data->start,data->len,data->behavior)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_madvise_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len,int32_t behavior) {
for (auto x: internal_registered_callback_sys_madvise){
    x(env,pc,start,len,behavior);
}
if (0 == ppp_on_sys_madvise_returned_num_cb) return;
sys_madvise_calldata* data = new sys_madvise_calldata;
data->pc = pc;
data->start = start;
data->len = len;
data->behavior = behavior;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_madvise_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_fcntl64;
void syscalls::register_call_sys_fcntl64(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_fcntl64.push_back(callback);
}
struct sys_fcntl64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t cmd;
uint32_t arg;
};
static Callback_RC sys_fcntl64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fcntl64_calldata* data = dynamic_cast<sys_fcntl64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fcntl64_returned, env,data->pc,data->fd,data->cmd,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fcntl64_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t cmd,uint32_t arg) {
for (auto x: internal_registered_callback_sys_fcntl64){
    x(env,pc,fd,cmd,arg);
}
if (0 == ppp_on_sys_fcntl64_returned_num_cb) return;
sys_fcntl64_calldata* data = new sys_fcntl64_calldata;
data->pc = pc;
data->fd = fd;
data->cmd = cmd;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fcntl64_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_gettid;
void syscalls::register_call_sys_gettid(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_gettid.push_back(callback);
}
struct sys_gettid_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_gettid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_gettid_calldata* data = dynamic_cast<sys_gettid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_gettid_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_gettid_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_gettid){
    x(env,pc);
}
if (0 == ppp_on_sys_gettid_returned_num_cb) return;
sys_gettid_calldata* data = new sys_gettid_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_gettid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint64_t, uint32_t)>> internal_registered_callback_sys_readahead;
void syscalls::register_call_sys_readahead(std::function<void(CPUState*, target_ulong, int32_t, uint64_t, uint32_t)> callback){
internal_registered_callback_sys_readahead.push_back(callback);
}
struct sys_readahead_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
uint64_t offset;
uint32_t count;
};
static Callback_RC sys_readahead_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_readahead_calldata* data = dynamic_cast<sys_readahead_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_readahead_returned, env,data->pc,data->fd,data->offset,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_readahead_callback(CPUState* env,target_ulong pc,int32_t fd,uint64_t offset,uint32_t count) {
for (auto x: internal_registered_callback_sys_readahead){
    x(env,pc,fd,offset,count);
}
if (0 == ppp_on_sys_readahead_returned_num_cb) return;
sys_readahead_calldata* data = new sys_readahead_calldata;
data->pc = pc;
data->fd = fd;
data->offset = offset;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_readahead_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_setxattr;
void syscalls::register_call_sys_setxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_setxattr.push_back(callback);
}
struct sys_setxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
target_ulong value;
uint32_t size;
int32_t flags;
};
static Callback_RC sys_setxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setxattr_calldata* data = dynamic_cast<sys_setxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setxattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr(),data->value,data->size,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name,target_ulong value,uint32_t size,int32_t flags) {
for (auto x: internal_registered_callback_sys_setxattr){
    x(env,pc,path,name,value,size,flags);
}
if (0 == ppp_on_sys_setxattr_returned_num_cb) return;
sys_setxattr_calldata* data = new sys_setxattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
data->value = value;
data->size = size;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_lsetxattr;
void syscalls::register_call_sys_lsetxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_lsetxattr.push_back(callback);
}
struct sys_lsetxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
target_ulong value;
uint32_t size;
int32_t flags;
};
static Callback_RC sys_lsetxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lsetxattr_calldata* data = dynamic_cast<sys_lsetxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lsetxattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr(),data->value,data->size,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lsetxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name,target_ulong value,uint32_t size,int32_t flags) {
for (auto x: internal_registered_callback_sys_lsetxattr){
    x(env,pc,path,name,value,size,flags);
}
if (0 == ppp_on_sys_lsetxattr_returned_num_cb) return;
sys_lsetxattr_calldata* data = new sys_lsetxattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
data->value = value;
data->size = size;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lsetxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_fsetxattr;
void syscalls::register_call_sys_fsetxattr(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_fsetxattr.push_back(callback);
}
struct sys_fsetxattr_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
syscalls::string name;
target_ulong value;
uint32_t size;
int32_t flags;
};
static Callback_RC sys_fsetxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fsetxattr_calldata* data = dynamic_cast<sys_fsetxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fsetxattr_returned, env,data->pc,data->fd,data->name.get_vaddr(),data->value,data->size,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fsetxattr_callback(CPUState* env,target_ulong pc,int32_t fd,syscalls::string name,target_ulong value,uint32_t size,int32_t flags) {
for (auto x: internal_registered_callback_sys_fsetxattr){
    x(env,pc,fd,name,value,size,flags);
}
if (0 == ppp_on_sys_fsetxattr_returned_num_cb) return;
sys_fsetxattr_calldata* data = new sys_fsetxattr_calldata;
data->pc = pc;
data->fd = fd;
data->name = name;
data->value = value;
data->size = size;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fsetxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t)>> internal_registered_callback_sys_getxattr;
void syscalls::register_call_sys_getxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_getxattr.push_back(callback);
}
struct sys_getxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
target_ulong value;
uint32_t size;
};
static Callback_RC sys_getxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getxattr_calldata* data = dynamic_cast<sys_getxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getxattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr(),data->value,data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name,target_ulong value,uint32_t size) {
for (auto x: internal_registered_callback_sys_getxattr){
    x(env,pc,path,name,value,size);
}
if (0 == ppp_on_sys_getxattr_returned_num_cb) return;
sys_getxattr_calldata* data = new sys_getxattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
data->value = value;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t)>> internal_registered_callback_sys_lgetxattr;
void syscalls::register_call_sys_lgetxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_lgetxattr.push_back(callback);
}
struct sys_lgetxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
target_ulong value;
uint32_t size;
};
static Callback_RC sys_lgetxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lgetxattr_calldata* data = dynamic_cast<sys_lgetxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lgetxattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr(),data->value,data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lgetxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name,target_ulong value,uint32_t size) {
for (auto x: internal_registered_callback_sys_lgetxattr){
    x(env,pc,path,name,value,size);
}
if (0 == ppp_on_sys_lgetxattr_returned_num_cb) return;
sys_lgetxattr_calldata* data = new sys_lgetxattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
data->value = value;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lgetxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, uint32_t)>> internal_registered_callback_sys_fgetxattr;
void syscalls::register_call_sys_fgetxattr(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_fgetxattr.push_back(callback);
}
struct sys_fgetxattr_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
syscalls::string name;
target_ulong value;
uint32_t size;
};
static Callback_RC sys_fgetxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fgetxattr_calldata* data = dynamic_cast<sys_fgetxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fgetxattr_returned, env,data->pc,data->fd,data->name.get_vaddr(),data->value,data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fgetxattr_callback(CPUState* env,target_ulong pc,int32_t fd,syscalls::string name,target_ulong value,uint32_t size) {
for (auto x: internal_registered_callback_sys_fgetxattr){
    x(env,pc,fd,name,value,size);
}
if (0 == ppp_on_sys_fgetxattr_returned_num_cb) return;
sys_fgetxattr_calldata* data = new sys_fgetxattr_calldata;
data->pc = pc;
data->fd = fd;
data->name = name;
data->value = value;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fgetxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, uint32_t)>> internal_registered_callback_sys_listxattr;
void syscalls::register_call_sys_listxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_listxattr.push_back(callback);
}
struct sys_listxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string list;
uint32_t size;
};
static Callback_RC sys_listxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_listxattr_calldata* data = dynamic_cast<sys_listxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_listxattr_returned, env,data->pc,data->path.get_vaddr(),data->list.get_vaddr(),data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_listxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string list,uint32_t size) {
for (auto x: internal_registered_callback_sys_listxattr){
    x(env,pc,path,list,size);
}
if (0 == ppp_on_sys_listxattr_returned_num_cb) return;
sys_listxattr_calldata* data = new sys_listxattr_calldata;
data->pc = pc;
data->path = path;
data->list = list;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_listxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, uint32_t)>> internal_registered_callback_sys_llistxattr;
void syscalls::register_call_sys_llistxattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_llistxattr.push_back(callback);
}
struct sys_llistxattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string list;
uint32_t size;
};
static Callback_RC sys_llistxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_llistxattr_calldata* data = dynamic_cast<sys_llistxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_llistxattr_returned, env,data->pc,data->path.get_vaddr(),data->list.get_vaddr(),data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_llistxattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string list,uint32_t size) {
for (auto x: internal_registered_callback_sys_llistxattr){
    x(env,pc,path,list,size);
}
if (0 == ppp_on_sys_llistxattr_returned_num_cb) return;
sys_llistxattr_calldata* data = new sys_llistxattr_calldata;
data->pc = pc;
data->path = path;
data->list = list;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_llistxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)>> internal_registered_callback_sys_flistxattr;
void syscalls::register_call_sys_flistxattr(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_flistxattr.push_back(callback);
}
struct sys_flistxattr_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
syscalls::string list;
uint32_t size;
};
static Callback_RC sys_flistxattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_flistxattr_calldata* data = dynamic_cast<sys_flistxattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_flistxattr_returned, env,data->pc,data->fd,data->list.get_vaddr(),data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_flistxattr_callback(CPUState* env,target_ulong pc,int32_t fd,syscalls::string list,uint32_t size) {
for (auto x: internal_registered_callback_sys_flistxattr){
    x(env,pc,fd,list,size);
}
if (0 == ppp_on_sys_flistxattr_returned_num_cb) return;
sys_flistxattr_calldata* data = new sys_flistxattr_calldata;
data->pc = pc;
data->fd = fd;
data->list = list;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_flistxattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_removexattr;
void syscalls::register_call_sys_removexattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_removexattr.push_back(callback);
}
struct sys_removexattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
};
static Callback_RC sys_removexattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_removexattr_calldata* data = dynamic_cast<sys_removexattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_removexattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_removexattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name) {
for (auto x: internal_registered_callback_sys_removexattr){
    x(env,pc,path,name);
}
if (0 == ppp_on_sys_removexattr_returned_num_cb) return;
sys_removexattr_calldata* data = new sys_removexattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_removexattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)>> internal_registered_callback_sys_lremovexattr;
void syscalls::register_call_sys_lremovexattr(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string)> callback){
internal_registered_callback_sys_lremovexattr.push_back(callback);
}
struct sys_lremovexattr_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
syscalls::string name;
};
static Callback_RC sys_lremovexattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lremovexattr_calldata* data = dynamic_cast<sys_lremovexattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lremovexattr_returned, env,data->pc,data->path.get_vaddr(),data->name.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lremovexattr_callback(CPUState* env,target_ulong pc,syscalls::string path,syscalls::string name) {
for (auto x: internal_registered_callback_sys_lremovexattr){
    x(env,pc,path,name);
}
if (0 == ppp_on_sys_lremovexattr_returned_num_cb) return;
sys_lremovexattr_calldata* data = new sys_lremovexattr_calldata;
data->pc = pc;
data->path = path;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lremovexattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string)>> internal_registered_callback_sys_fremovexattr;
void syscalls::register_call_sys_fremovexattr(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string)> callback){
internal_registered_callback_sys_fremovexattr.push_back(callback);
}
struct sys_fremovexattr_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
syscalls::string name;
};
static Callback_RC sys_fremovexattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fremovexattr_calldata* data = dynamic_cast<sys_fremovexattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fremovexattr_returned, env,data->pc,data->fd,data->name.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fremovexattr_callback(CPUState* env,target_ulong pc,int32_t fd,syscalls::string name) {
for (auto x: internal_registered_callback_sys_fremovexattr){
    x(env,pc,fd,name);
}
if (0 == ppp_on_sys_fremovexattr_returned_num_cb) return;
sys_fremovexattr_calldata* data = new sys_fremovexattr_calldata;
data->pc = pc;
data->fd = fd;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fremovexattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_tkill;
void syscalls::register_call_sys_tkill(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_tkill.push_back(callback);
}
struct sys_tkill_calldata : public CallbackData {
target_ulong pc;
int32_t pid;
int32_t sig;
};
static Callback_RC sys_tkill_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_tkill_calldata* data = dynamic_cast<sys_tkill_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_tkill_returned, env,data->pc,data->pid,data->sig)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_tkill_callback(CPUState* env,target_ulong pc,int32_t pid,int32_t sig) {
for (auto x: internal_registered_callback_sys_tkill){
    x(env,pc,pid,sig);
}
if (0 == ppp_on_sys_tkill_returned_num_cb) return;
sys_tkill_calldata* data = new sys_tkill_calldata;
data->pc = pc;
data->pid = pid;
data->sig = sig;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_tkill_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_sendfile64;
void syscalls::register_call_sys_sendfile64(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_sendfile64.push_back(callback);
}
struct sys_sendfile64_calldata : public CallbackData {
target_ulong pc;
int32_t out_fd;
int32_t in_fd;
target_ulong offset;
uint32_t count;
};
static Callback_RC sys_sendfile64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sendfile64_calldata* data = dynamic_cast<sys_sendfile64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sendfile64_returned, env,data->pc,data->out_fd,data->in_fd,data->offset,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sendfile64_callback(CPUState* env,target_ulong pc,int32_t out_fd,int32_t in_fd,target_ulong offset,uint32_t count) {
for (auto x: internal_registered_callback_sys_sendfile64){
    x(env,pc,out_fd,in_fd,offset,count);
}
if (0 == ppp_on_sys_sendfile64_returned_num_cb) return;
sys_sendfile64_calldata* data = new sys_sendfile64_calldata;
data->pc = pc;
data->out_fd = out_fd;
data->in_fd = in_fd;
data->offset = offset;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sendfile64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, int32_t, uint32_t, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_futex;
void syscalls::register_call_sys_futex(std::function<void(CPUState*, target_ulong, target_ulong, int32_t, uint32_t, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_futex.push_back(callback);
}
struct sys_futex_calldata : public CallbackData {
target_ulong pc;
target_ulong uaddr;
int32_t op;
uint32_t val;
target_ulong utime;
target_ulong uaddr2;
uint32_t val3;
};
static Callback_RC sys_futex_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_futex_calldata* data = dynamic_cast<sys_futex_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_futex_returned, env,data->pc,data->uaddr,data->op,data->val,data->utime,data->uaddr2,data->val3)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_futex_callback(CPUState* env,target_ulong pc,target_ulong uaddr,int32_t op,uint32_t val,target_ulong utime,target_ulong uaddr2,uint32_t val3) {
for (auto x: internal_registered_callback_sys_futex){
    x(env,pc,uaddr,op,val,utime,uaddr2,val3);
}
if (0 == ppp_on_sys_futex_returned_num_cb) return;
sys_futex_calldata* data = new sys_futex_calldata;
data->pc = pc;
data->uaddr = uaddr;
data->op = op;
data->val = val;
data->utime = utime;
data->uaddr2 = uaddr2;
data->val3 = val3;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_futex_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_sched_setaffinity;
void syscalls::register_call_sys_sched_setaffinity(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_setaffinity.push_back(callback);
}
struct sys_sched_setaffinity_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
uint32_t len;
target_ulong user_mask_ptr;
};
static Callback_RC sys_sched_setaffinity_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_setaffinity_calldata* data = dynamic_cast<sys_sched_setaffinity_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_setaffinity_returned, env,data->pc,data->pid,data->len,data->user_mask_ptr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_setaffinity_callback(CPUState* env,target_ulong pc,uint32_t pid,uint32_t len,target_ulong user_mask_ptr) {
for (auto x: internal_registered_callback_sys_sched_setaffinity){
    x(env,pc,pid,len,user_mask_ptr);
}
if (0 == ppp_on_sys_sched_setaffinity_returned_num_cb) return;
sys_sched_setaffinity_calldata* data = new sys_sched_setaffinity_calldata;
data->pc = pc;
data->pid = pid;
data->len = len;
data->user_mask_ptr = user_mask_ptr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_setaffinity_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_sched_getaffinity;
void syscalls::register_call_sys_sched_getaffinity(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_sched_getaffinity.push_back(callback);
}
struct sys_sched_getaffinity_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
uint32_t len;
target_ulong user_mask_ptr;
};
static Callback_RC sys_sched_getaffinity_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sched_getaffinity_calldata* data = dynamic_cast<sys_sched_getaffinity_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sched_getaffinity_returned, env,data->pc,data->pid,data->len,data->user_mask_ptr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sched_getaffinity_callback(CPUState* env,target_ulong pc,uint32_t pid,uint32_t len,target_ulong user_mask_ptr) {
for (auto x: internal_registered_callback_sys_sched_getaffinity){
    x(env,pc,pid,len,user_mask_ptr);
}
if (0 == ppp_on_sys_sched_getaffinity_returned_num_cb) return;
sys_sched_getaffinity_calldata* data = new sys_sched_getaffinity_calldata;
data->pc = pc;
data->pid = pid;
data->len = len;
data->user_mask_ptr = user_mask_ptr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sched_getaffinity_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_io_setup;
void syscalls::register_call_sys_io_setup(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_io_setup.push_back(callback);
}
struct sys_io_setup_calldata : public CallbackData {
target_ulong pc;
uint32_t nr_reqs;
target_ulong ctx;
};
static Callback_RC sys_io_setup_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_io_setup_calldata* data = dynamic_cast<sys_io_setup_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_io_setup_returned, env,data->pc,data->nr_reqs,data->ctx)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_io_setup_callback(CPUState* env,target_ulong pc,uint32_t nr_reqs,target_ulong ctx) {
for (auto x: internal_registered_callback_sys_io_setup){
    x(env,pc,nr_reqs,ctx);
}
if (0 == ppp_on_sys_io_setup_returned_num_cb) return;
sys_io_setup_calldata* data = new sys_io_setup_calldata;
data->pc = pc;
data->nr_reqs = nr_reqs;
data->ctx = ctx;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_io_setup_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_io_destroy;
void syscalls::register_call_sys_io_destroy(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_io_destroy.push_back(callback);
}
struct sys_io_destroy_calldata : public CallbackData {
target_ulong pc;
uint32_t ctx;
};
static Callback_RC sys_io_destroy_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_io_destroy_calldata* data = dynamic_cast<sys_io_destroy_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_io_destroy_returned, env,data->pc,data->ctx)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_io_destroy_callback(CPUState* env,target_ulong pc,uint32_t ctx) {
for (auto x: internal_registered_callback_sys_io_destroy){
    x(env,pc,ctx);
}
if (0 == ppp_on_sys_io_destroy_returned_num_cb) return;
sys_io_destroy_calldata* data = new sys_io_destroy_calldata;
data->pc = pc;
data->ctx = ctx;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_io_destroy_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_io_getevents;
void syscalls::register_call_sys_io_getevents(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_io_getevents.push_back(callback);
}
struct sys_io_getevents_calldata : public CallbackData {
target_ulong pc;
uint32_t ctx_id;
int32_t min_nr;
int32_t nr;
target_ulong events;
target_ulong timeout;
};
static Callback_RC sys_io_getevents_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_io_getevents_calldata* data = dynamic_cast<sys_io_getevents_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_io_getevents_returned, env,data->pc,data->ctx_id,data->min_nr,data->nr,data->events,data->timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_io_getevents_callback(CPUState* env,target_ulong pc,uint32_t ctx_id,int32_t min_nr,int32_t nr,target_ulong events,target_ulong timeout) {
for (auto x: internal_registered_callback_sys_io_getevents){
    x(env,pc,ctx_id,min_nr,nr,events,timeout);
}
if (0 == ppp_on_sys_io_getevents_returned_num_cb) return;
sys_io_getevents_calldata* data = new sys_io_getevents_calldata;
data->pc = pc;
data->ctx_id = ctx_id;
data->min_nr = min_nr;
data->nr = nr;
data->events = events;
data->timeout = timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_io_getevents_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong)>> internal_registered_callback_sys_io_submit;
void syscalls::register_call_sys_io_submit(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_io_submit.push_back(callback);
}
struct sys_io_submit_calldata : public CallbackData {
target_ulong pc;
uint32_t arg0;
int32_t arg1;
target_ulong arg2;
};
static Callback_RC sys_io_submit_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_io_submit_calldata* data = dynamic_cast<sys_io_submit_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_io_submit_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_io_submit_callback(CPUState* env,target_ulong pc,uint32_t arg0,int32_t arg1,target_ulong arg2) {
for (auto x: internal_registered_callback_sys_io_submit){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_io_submit_returned_num_cb) return;
sys_io_submit_calldata* data = new sys_io_submit_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_io_submit_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_io_cancel;
void syscalls::register_call_sys_io_cancel(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_io_cancel.push_back(callback);
}
struct sys_io_cancel_calldata : public CallbackData {
target_ulong pc;
uint32_t ctx_id;
target_ulong iocb;
target_ulong result;
};
static Callback_RC sys_io_cancel_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_io_cancel_calldata* data = dynamic_cast<sys_io_cancel_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_io_cancel_returned, env,data->pc,data->ctx_id,data->iocb,data->result)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_io_cancel_callback(CPUState* env,target_ulong pc,uint32_t ctx_id,target_ulong iocb,target_ulong result) {
for (auto x: internal_registered_callback_sys_io_cancel){
    x(env,pc,ctx_id,iocb,result);
}
if (0 == ppp_on_sys_io_cancel_returned_num_cb) return;
sys_io_cancel_calldata* data = new sys_io_cancel_calldata;
data->pc = pc;
data->ctx_id = ctx_id;
data->iocb = iocb;
data->result = result;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_io_cancel_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_exit_group;
void syscalls::register_call_sys_exit_group(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_exit_group.push_back(callback);
}
struct sys_exit_group_calldata : public CallbackData {
target_ulong pc;
int32_t error_code;
};
static Callback_RC sys_exit_group_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_exit_group_calldata* data = dynamic_cast<sys_exit_group_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_exit_group_returned, env,data->pc,data->error_code)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_exit_group_callback(CPUState* env,target_ulong pc,int32_t error_code) {
for (auto x: internal_registered_callback_sys_exit_group){
    x(env,pc,error_code);
}
if (0 == ppp_on_sys_exit_group_returned_num_cb) return;
sys_exit_group_calldata* data = new sys_exit_group_calldata;
data->pc = pc;
data->error_code = error_code;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_exit_group_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint64_t, target_ulong, uint32_t)>> internal_registered_callback_sys_lookup_dcookie;
void syscalls::register_call_sys_lookup_dcookie(std::function<void(CPUState*, target_ulong, uint64_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_lookup_dcookie.push_back(callback);
}
struct sys_lookup_dcookie_calldata : public CallbackData {
target_ulong pc;
uint64_t cookie64;
target_ulong buf;
uint32_t len;
};
static Callback_RC sys_lookup_dcookie_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_lookup_dcookie_calldata* data = dynamic_cast<sys_lookup_dcookie_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_lookup_dcookie_returned, env,data->pc,data->cookie64,data->buf,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_lookup_dcookie_callback(CPUState* env,target_ulong pc,uint64_t cookie64,target_ulong buf,uint32_t len) {
for (auto x: internal_registered_callback_sys_lookup_dcookie){
    x(env,pc,cookie64,buf,len);
}
if (0 == ppp_on_sys_lookup_dcookie_returned_num_cb) return;
sys_lookup_dcookie_calldata* data = new sys_lookup_dcookie_calldata;
data->pc = pc;
data->cookie64 = cookie64;
data->buf = buf;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_lookup_dcookie_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_epoll_create;
void syscalls::register_call_sys_epoll_create(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_epoll_create.push_back(callback);
}
struct sys_epoll_create_calldata : public CallbackData {
target_ulong pc;
int32_t size;
};
static Callback_RC sys_epoll_create_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_epoll_create_calldata* data = dynamic_cast<sys_epoll_create_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_epoll_create_returned, env,data->pc,data->size)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_epoll_create_callback(CPUState* env,target_ulong pc,int32_t size) {
for (auto x: internal_registered_callback_sys_epoll_create){
    x(env,pc,size);
}
if (0 == ppp_on_sys_epoll_create_returned_num_cb) return;
sys_epoll_create_calldata* data = new sys_epoll_create_calldata;
data->pc = pc;
data->size = size;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_epoll_create_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, target_ulong)>> internal_registered_callback_sys_epoll_ctl;
void syscalls::register_call_sys_epoll_ctl(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_epoll_ctl.push_back(callback);
}
struct sys_epoll_ctl_calldata : public CallbackData {
target_ulong pc;
int32_t epfd;
int32_t op;
int32_t fd;
target_ulong event;
};
static Callback_RC sys_epoll_ctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_epoll_ctl_calldata* data = dynamic_cast<sys_epoll_ctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_epoll_ctl_returned, env,data->pc,data->epfd,data->op,data->fd,data->event)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_epoll_ctl_callback(CPUState* env,target_ulong pc,int32_t epfd,int32_t op,int32_t fd,target_ulong event) {
for (auto x: internal_registered_callback_sys_epoll_ctl){
    x(env,pc,epfd,op,fd,event);
}
if (0 == ppp_on_sys_epoll_ctl_returned_num_cb) return;
sys_epoll_ctl_calldata* data = new sys_epoll_ctl_calldata;
data->pc = pc;
data->epfd = epfd;
data->op = op;
data->fd = fd;
data->event = event;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_epoll_ctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_epoll_wait;
void syscalls::register_call_sys_epoll_wait(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_epoll_wait.push_back(callback);
}
struct sys_epoll_wait_calldata : public CallbackData {
target_ulong pc;
int32_t epfd;
target_ulong events;
int32_t maxevents;
int32_t timeout;
};
static Callback_RC sys_epoll_wait_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_epoll_wait_calldata* data = dynamic_cast<sys_epoll_wait_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_epoll_wait_returned, env,data->pc,data->epfd,data->events,data->maxevents,data->timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_epoll_wait_callback(CPUState* env,target_ulong pc,int32_t epfd,target_ulong events,int32_t maxevents,int32_t timeout) {
for (auto x: internal_registered_callback_sys_epoll_wait){
    x(env,pc,epfd,events,maxevents,timeout);
}
if (0 == ppp_on_sys_epoll_wait_returned_num_cb) return;
sys_epoll_wait_calldata* data = new sys_epoll_wait_calldata;
data->pc = pc;
data->epfd = epfd;
data->events = events;
data->maxevents = maxevents;
data->timeout = timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_epoll_wait_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_remap_file_pages;
void syscalls::register_call_sys_remap_file_pages(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_remap_file_pages.push_back(callback);
}
struct sys_remap_file_pages_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t size;
uint32_t prot;
uint32_t pgoff;
uint32_t flags;
};
static Callback_RC sys_remap_file_pages_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_remap_file_pages_calldata* data = dynamic_cast<sys_remap_file_pages_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_remap_file_pages_returned, env,data->pc,data->start,data->size,data->prot,data->pgoff,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_remap_file_pages_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t size,uint32_t prot,uint32_t pgoff,uint32_t flags) {
for (auto x: internal_registered_callback_sys_remap_file_pages){
    x(env,pc,start,size,prot,pgoff,flags);
}
if (0 == ppp_on_sys_remap_file_pages_returned_num_cb) return;
sys_remap_file_pages_calldata* data = new sys_remap_file_pages_calldata;
data->pc = pc;
data->start = start;
data->size = size;
data->prot = prot;
data->pgoff = pgoff;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_remap_file_pages_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong)>> internal_registered_callback_sys_set_tid_address;
void syscalls::register_call_sys_set_tid_address(std::function<void(CPUState*, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_set_tid_address.push_back(callback);
}
struct sys_set_tid_address_calldata : public CallbackData {
target_ulong pc;
target_ulong tidptr;
};
static Callback_RC sys_set_tid_address_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_set_tid_address_calldata* data = dynamic_cast<sys_set_tid_address_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_set_tid_address_returned, env,data->pc,data->tidptr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_set_tid_address_callback(CPUState* env,target_ulong pc,target_ulong tidptr) {
for (auto x: internal_registered_callback_sys_set_tid_address){
    x(env,pc,tidptr);
}
if (0 == ppp_on_sys_set_tid_address_returned_num_cb) return;
sys_set_tid_address_calldata* data = new sys_set_tid_address_calldata;
data->pc = pc;
data->tidptr = tidptr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_set_tid_address_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_timer_create;
void syscalls::register_call_sys_timer_create(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_timer_create.push_back(callback);
}
struct sys_timer_create_calldata : public CallbackData {
target_ulong pc;
uint32_t which_clock;
target_ulong timer_event_spec;
target_ulong created_timer_id;
};
static Callback_RC sys_timer_create_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timer_create_calldata* data = dynamic_cast<sys_timer_create_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timer_create_returned, env,data->pc,data->which_clock,data->timer_event_spec,data->created_timer_id)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timer_create_callback(CPUState* env,target_ulong pc,uint32_t which_clock,target_ulong timer_event_spec,target_ulong created_timer_id) {
for (auto x: internal_registered_callback_sys_timer_create){
    x(env,pc,which_clock,timer_event_spec,created_timer_id);
}
if (0 == ppp_on_sys_timer_create_returned_num_cb) return;
sys_timer_create_calldata* data = new sys_timer_create_calldata;
data->pc = pc;
data->which_clock = which_clock;
data->timer_event_spec = timer_event_spec;
data->created_timer_id = created_timer_id;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timer_create_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_timer_settime;
void syscalls::register_call_sys_timer_settime(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_timer_settime.push_back(callback);
}
struct sys_timer_settime_calldata : public CallbackData {
target_ulong pc;
uint32_t timer_id;
int32_t flags;
target_ulong new_setting;
target_ulong old_setting;
};
static Callback_RC sys_timer_settime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timer_settime_calldata* data = dynamic_cast<sys_timer_settime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timer_settime_returned, env,data->pc,data->timer_id,data->flags,data->new_setting,data->old_setting)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timer_settime_callback(CPUState* env,target_ulong pc,uint32_t timer_id,int32_t flags,target_ulong new_setting,target_ulong old_setting) {
for (auto x: internal_registered_callback_sys_timer_settime){
    x(env,pc,timer_id,flags,new_setting,old_setting);
}
if (0 == ppp_on_sys_timer_settime_returned_num_cb) return;
sys_timer_settime_calldata* data = new sys_timer_settime_calldata;
data->pc = pc;
data->timer_id = timer_id;
data->flags = flags;
data->new_setting = new_setting;
data->old_setting = old_setting;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timer_settime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_timer_gettime;
void syscalls::register_call_sys_timer_gettime(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_timer_gettime.push_back(callback);
}
struct sys_timer_gettime_calldata : public CallbackData {
target_ulong pc;
uint32_t timer_id;
target_ulong setting;
};
static Callback_RC sys_timer_gettime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timer_gettime_calldata* data = dynamic_cast<sys_timer_gettime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timer_gettime_returned, env,data->pc,data->timer_id,data->setting)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timer_gettime_callback(CPUState* env,target_ulong pc,uint32_t timer_id,target_ulong setting) {
for (auto x: internal_registered_callback_sys_timer_gettime){
    x(env,pc,timer_id,setting);
}
if (0 == ppp_on_sys_timer_gettime_returned_num_cb) return;
sys_timer_gettime_calldata* data = new sys_timer_gettime_calldata;
data->pc = pc;
data->timer_id = timer_id;
data->setting = setting;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timer_gettime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_timer_getoverrun;
void syscalls::register_call_sys_timer_getoverrun(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_timer_getoverrun.push_back(callback);
}
struct sys_timer_getoverrun_calldata : public CallbackData {
target_ulong pc;
uint32_t timer_id;
};
static Callback_RC sys_timer_getoverrun_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timer_getoverrun_calldata* data = dynamic_cast<sys_timer_getoverrun_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timer_getoverrun_returned, env,data->pc,data->timer_id)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timer_getoverrun_callback(CPUState* env,target_ulong pc,uint32_t timer_id) {
for (auto x: internal_registered_callback_sys_timer_getoverrun){
    x(env,pc,timer_id);
}
if (0 == ppp_on_sys_timer_getoverrun_returned_num_cb) return;
sys_timer_getoverrun_calldata* data = new sys_timer_getoverrun_calldata;
data->pc = pc;
data->timer_id = timer_id;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timer_getoverrun_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_timer_delete;
void syscalls::register_call_sys_timer_delete(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_timer_delete.push_back(callback);
}
struct sys_timer_delete_calldata : public CallbackData {
target_ulong pc;
uint32_t timer_id;
};
static Callback_RC sys_timer_delete_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timer_delete_calldata* data = dynamic_cast<sys_timer_delete_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timer_delete_returned, env,data->pc,data->timer_id)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timer_delete_callback(CPUState* env,target_ulong pc,uint32_t timer_id) {
for (auto x: internal_registered_callback_sys_timer_delete){
    x(env,pc,timer_id);
}
if (0 == ppp_on_sys_timer_delete_returned_num_cb) return;
sys_timer_delete_calldata* data = new sys_timer_delete_calldata;
data->pc = pc;
data->timer_id = timer_id;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timer_delete_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_clock_settime;
void syscalls::register_call_sys_clock_settime(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_clock_settime.push_back(callback);
}
struct sys_clock_settime_calldata : public CallbackData {
target_ulong pc;
uint32_t which_clock;
target_ulong tp;
};
static Callback_RC sys_clock_settime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_clock_settime_calldata* data = dynamic_cast<sys_clock_settime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_clock_settime_returned, env,data->pc,data->which_clock,data->tp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_clock_settime_callback(CPUState* env,target_ulong pc,uint32_t which_clock,target_ulong tp) {
for (auto x: internal_registered_callback_sys_clock_settime){
    x(env,pc,which_clock,tp);
}
if (0 == ppp_on_sys_clock_settime_returned_num_cb) return;
sys_clock_settime_calldata* data = new sys_clock_settime_calldata;
data->pc = pc;
data->which_clock = which_clock;
data->tp = tp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_clock_settime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_clock_gettime;
void syscalls::register_call_sys_clock_gettime(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_clock_gettime.push_back(callback);
}
struct sys_clock_gettime_calldata : public CallbackData {
target_ulong pc;
uint32_t which_clock;
target_ulong tp;
};
static Callback_RC sys_clock_gettime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_clock_gettime_calldata* data = dynamic_cast<sys_clock_gettime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_clock_gettime_returned, env,data->pc,data->which_clock,data->tp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_clock_gettime_callback(CPUState* env,target_ulong pc,uint32_t which_clock,target_ulong tp) {
for (auto x: internal_registered_callback_sys_clock_gettime){
    x(env,pc,which_clock,tp);
}
if (0 == ppp_on_sys_clock_gettime_returned_num_cb) return;
sys_clock_gettime_calldata* data = new sys_clock_gettime_calldata;
data->pc = pc;
data->which_clock = which_clock;
data->tp = tp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_clock_gettime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_clock_getres;
void syscalls::register_call_sys_clock_getres(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_clock_getres.push_back(callback);
}
struct sys_clock_getres_calldata : public CallbackData {
target_ulong pc;
uint32_t which_clock;
target_ulong tp;
};
static Callback_RC sys_clock_getres_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_clock_getres_calldata* data = dynamic_cast<sys_clock_getres_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_clock_getres_returned, env,data->pc,data->which_clock,data->tp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_clock_getres_callback(CPUState* env,target_ulong pc,uint32_t which_clock,target_ulong tp) {
for (auto x: internal_registered_callback_sys_clock_getres){
    x(env,pc,which_clock,tp);
}
if (0 == ppp_on_sys_clock_getres_returned_num_cb) return;
sys_clock_getres_calldata* data = new sys_clock_getres_calldata;
data->pc = pc;
data->which_clock = which_clock;
data->tp = tp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_clock_getres_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_clock_nanosleep;
void syscalls::register_call_sys_clock_nanosleep(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_clock_nanosleep.push_back(callback);
}
struct sys_clock_nanosleep_calldata : public CallbackData {
target_ulong pc;
uint32_t which_clock;
int32_t flags;
target_ulong rqtp;
target_ulong rmtp;
};
static Callback_RC sys_clock_nanosleep_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_clock_nanosleep_calldata* data = dynamic_cast<sys_clock_nanosleep_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_clock_nanosleep_returned, env,data->pc,data->which_clock,data->flags,data->rqtp,data->rmtp)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_clock_nanosleep_callback(CPUState* env,target_ulong pc,uint32_t which_clock,int32_t flags,target_ulong rqtp,target_ulong rmtp) {
for (auto x: internal_registered_callback_sys_clock_nanosleep){
    x(env,pc,which_clock,flags,rqtp,rmtp);
}
if (0 == ppp_on_sys_clock_nanosleep_returned_num_cb) return;
sys_clock_nanosleep_calldata* data = new sys_clock_nanosleep_calldata;
data->pc = pc;
data->which_clock = which_clock;
data->flags = flags;
data->rqtp = rqtp;
data->rmtp = rmtp;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_clock_nanosleep_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, target_ulong)>> internal_registered_callback_sys_statfs64;
void syscalls::register_call_sys_statfs64(std::function<void(CPUState*, target_ulong, syscalls::string, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_statfs64.push_back(callback);
}
struct sys_statfs64_calldata : public CallbackData {
target_ulong pc;
syscalls::string path;
uint32_t sz;
target_ulong buf;
};
static Callback_RC sys_statfs64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_statfs64_calldata* data = dynamic_cast<sys_statfs64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_statfs64_returned, env,data->pc,data->path.get_vaddr(),data->sz,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_statfs64_callback(CPUState* env,target_ulong pc,syscalls::string path,uint32_t sz,target_ulong buf) {
for (auto x: internal_registered_callback_sys_statfs64){
    x(env,pc,path,sz,buf);
}
if (0 == ppp_on_sys_statfs64_returned_num_cb) return;
sys_statfs64_calldata* data = new sys_statfs64_calldata;
data->pc = pc;
data->path = path;
data->sz = sz;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_statfs64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_fstatfs64;
void syscalls::register_call_sys_fstatfs64(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_fstatfs64.push_back(callback);
}
struct sys_fstatfs64_calldata : public CallbackData {
target_ulong pc;
uint32_t fd;
uint32_t sz;
target_ulong buf;
};
static Callback_RC sys_fstatfs64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fstatfs64_calldata* data = dynamic_cast<sys_fstatfs64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fstatfs64_returned, env,data->pc,data->fd,data->sz,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fstatfs64_callback(CPUState* env,target_ulong pc,uint32_t fd,uint32_t sz,target_ulong buf) {
for (auto x: internal_registered_callback_sys_fstatfs64){
    x(env,pc,fd,sz,buf);
}
if (0 == ppp_on_sys_fstatfs64_returned_num_cb) return;
sys_fstatfs64_calldata* data = new sys_fstatfs64_calldata;
data->pc = pc;
data->fd = fd;
data->sz = sz;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fstatfs64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)>> internal_registered_callback_sys_tgkill;
void syscalls::register_call_sys_tgkill(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_tgkill.push_back(callback);
}
struct sys_tgkill_calldata : public CallbackData {
target_ulong pc;
int32_t tgid;
int32_t pid;
int32_t sig;
};
static Callback_RC sys_tgkill_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_tgkill_calldata* data = dynamic_cast<sys_tgkill_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_tgkill_returned, env,data->pc,data->tgid,data->pid,data->sig)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_tgkill_callback(CPUState* env,target_ulong pc,int32_t tgid,int32_t pid,int32_t sig) {
for (auto x: internal_registered_callback_sys_tgkill){
    x(env,pc,tgid,pid,sig);
}
if (0 == ppp_on_sys_tgkill_returned_num_cb) return;
sys_tgkill_calldata* data = new sys_tgkill_calldata;
data->pc = pc;
data->tgid = tgid;
data->pid = pid;
data->sig = sig;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_tgkill_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)>> internal_registered_callback_sys_utimes;
void syscalls::register_call_sys_utimes(std::function<void(CPUState*, target_ulong, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_utimes.push_back(callback);
}
struct sys_utimes_calldata : public CallbackData {
target_ulong pc;
syscalls::string filename;
target_ulong utimes;
};
static Callback_RC sys_utimes_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_utimes_calldata* data = dynamic_cast<sys_utimes_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_utimes_returned, env,data->pc,data->filename.get_vaddr(),data->utimes)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_utimes_callback(CPUState* env,target_ulong pc,syscalls::string filename,target_ulong utimes) {
for (auto x: internal_registered_callback_sys_utimes){
    x(env,pc,filename,utimes);
}
if (0 == ppp_on_sys_utimes_returned_num_cb) return;
sys_utimes_calldata* data = new sys_utimes_calldata;
data->pc = pc;
data->filename = filename;
data->utimes = utimes;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_utimes_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint64_t, uint64_t)>> internal_registered_callback_sys_arm_fadvise64_64;
void syscalls::register_call_sys_arm_fadvise64_64(std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint64_t, uint64_t)> callback){
internal_registered_callback_sys_arm_fadvise64_64.push_back(callback);
}
struct sys_arm_fadvise64_64_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
int32_t advice;
uint64_t offset;
uint64_t len;
};
static Callback_RC sys_arm_fadvise64_64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_arm_fadvise64_64_calldata* data = dynamic_cast<sys_arm_fadvise64_64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_arm_fadvise64_64_returned, env,data->pc,data->fd,data->advice,data->offset,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_arm_fadvise64_64_callback(CPUState* env,target_ulong pc,int32_t fd,int32_t advice,uint64_t offset,uint64_t len) {
for (auto x: internal_registered_callback_sys_arm_fadvise64_64){
    x(env,pc,fd,advice,offset,len);
}
if (0 == ppp_on_sys_arm_fadvise64_64_returned_num_cb) return;
sys_arm_fadvise64_64_calldata* data = new sys_arm_fadvise64_64_calldata;
data->pc = pc;
data->fd = fd;
data->advice = advice;
data->offset = offset;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_arm_fadvise64_64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_pciconfig_iobase;
void syscalls::register_call_sys_pciconfig_iobase(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_pciconfig_iobase.push_back(callback);
}
struct sys_pciconfig_iobase_calldata : public CallbackData {
target_ulong pc;
int32_t which;
uint32_t bus;
uint32_t devfn;
};
static Callback_RC sys_pciconfig_iobase_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pciconfig_iobase_calldata* data = dynamic_cast<sys_pciconfig_iobase_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pciconfig_iobase_returned, env,data->pc,data->which,data->bus,data->devfn)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pciconfig_iobase_callback(CPUState* env,target_ulong pc,int32_t which,uint32_t bus,uint32_t devfn) {
for (auto x: internal_registered_callback_sys_pciconfig_iobase){
    x(env,pc,which,bus,devfn);
}
if (0 == ppp_on_sys_pciconfig_iobase_returned_num_cb) return;
sys_pciconfig_iobase_calldata* data = new sys_pciconfig_iobase_calldata;
data->pc = pc;
data->which = which;
data->bus = bus;
data->devfn = devfn;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pciconfig_iobase_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_pciconfig_read;
void syscalls::register_call_sys_pciconfig_read(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_pciconfig_read.push_back(callback);
}
struct sys_pciconfig_read_calldata : public CallbackData {
target_ulong pc;
uint32_t bus;
uint32_t dfn;
uint32_t off;
uint32_t len;
target_ulong buf;
};
static Callback_RC sys_pciconfig_read_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pciconfig_read_calldata* data = dynamic_cast<sys_pciconfig_read_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pciconfig_read_returned, env,data->pc,data->bus,data->dfn,data->off,data->len,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pciconfig_read_callback(CPUState* env,target_ulong pc,uint32_t bus,uint32_t dfn,uint32_t off,uint32_t len,target_ulong buf) {
for (auto x: internal_registered_callback_sys_pciconfig_read){
    x(env,pc,bus,dfn,off,len,buf);
}
if (0 == ppp_on_sys_pciconfig_read_returned_num_cb) return;
sys_pciconfig_read_calldata* data = new sys_pciconfig_read_calldata;
data->pc = pc;
data->bus = bus;
data->dfn = dfn;
data->off = off;
data->len = len;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pciconfig_read_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_pciconfig_write;
void syscalls::register_call_sys_pciconfig_write(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_pciconfig_write.push_back(callback);
}
struct sys_pciconfig_write_calldata : public CallbackData {
target_ulong pc;
uint32_t bus;
uint32_t dfn;
uint32_t off;
uint32_t len;
target_ulong buf;
};
static Callback_RC sys_pciconfig_write_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pciconfig_write_calldata* data = dynamic_cast<sys_pciconfig_write_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pciconfig_write_returned, env,data->pc,data->bus,data->dfn,data->off,data->len,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pciconfig_write_callback(CPUState* env,target_ulong pc,uint32_t bus,uint32_t dfn,uint32_t off,uint32_t len,target_ulong buf) {
for (auto x: internal_registered_callback_sys_pciconfig_write){
    x(env,pc,bus,dfn,off,len,buf);
}
if (0 == ppp_on_sys_pciconfig_write_returned_num_cb) return;
sys_pciconfig_write_calldata* data = new sys_pciconfig_write_calldata;
data->pc = pc;
data->bus = bus;
data->dfn = dfn;
data->off = off;
data->len = len;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pciconfig_write_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_mq_open;
void syscalls::register_call_sys_mq_open(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_mq_open.push_back(callback);
}
struct sys_mq_open_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
int32_t oflag;
uint32_t mode;
target_ulong attr;
};
static Callback_RC sys_mq_open_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_open_calldata* data = dynamic_cast<sys_mq_open_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_open_returned, env,data->pc,data->name.get_vaddr(),data->oflag,data->mode,data->attr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_open_callback(CPUState* env,target_ulong pc,syscalls::string name,int32_t oflag,uint32_t mode,target_ulong attr) {
for (auto x: internal_registered_callback_sys_mq_open){
    x(env,pc,name,oflag,mode,attr);
}
if (0 == ppp_on_sys_mq_open_returned_num_cb) return;
sys_mq_open_calldata* data = new sys_mq_open_calldata;
data->pc = pc;
data->name = name;
data->oflag = oflag;
data->mode = mode;
data->attr = attr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_open_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_mq_unlink;
void syscalls::register_call_sys_mq_unlink(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_mq_unlink.push_back(callback);
}
struct sys_mq_unlink_calldata : public CallbackData {
target_ulong pc;
syscalls::string name;
};
static Callback_RC sys_mq_unlink_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_unlink_calldata* data = dynamic_cast<sys_mq_unlink_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_unlink_returned, env,data->pc,data->name.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_unlink_callback(CPUState* env,target_ulong pc,syscalls::string name) {
for (auto x: internal_registered_callback_sys_mq_unlink){
    x(env,pc,name);
}
if (0 == ppp_on_sys_mq_unlink_returned_num_cb) return;
sys_mq_unlink_calldata* data = new sys_mq_unlink_calldata;
data->pc = pc;
data->name = name;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_unlink_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_sys_mq_timedsend;
void syscalls::register_call_sys_mq_timedsend(std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_mq_timedsend.push_back(callback);
}
struct sys_mq_timedsend_calldata : public CallbackData {
target_ulong pc;
uint32_t mqdes;
syscalls::string msg_ptr;
uint32_t msg_len;
uint32_t msg_prio;
target_ulong abs_timeout;
};
static Callback_RC sys_mq_timedsend_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_timedsend_calldata* data = dynamic_cast<sys_mq_timedsend_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_timedsend_returned, env,data->pc,data->mqdes,data->msg_ptr.get_vaddr(),data->msg_len,data->msg_prio,data->abs_timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_timedsend_callback(CPUState* env,target_ulong pc,uint32_t mqdes,syscalls::string msg_ptr,uint32_t msg_len,uint32_t msg_prio,target_ulong abs_timeout) {
for (auto x: internal_registered_callback_sys_mq_timedsend){
    x(env,pc,mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
}
if (0 == ppp_on_sys_mq_timedsend_returned_num_cb) return;
sys_mq_timedsend_calldata* data = new sys_mq_timedsend_calldata;
data->pc = pc;
data->mqdes = mqdes;
data->msg_ptr = msg_ptr;
data->msg_len = msg_len;
data->msg_prio = msg_prio;
data->abs_timeout = abs_timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_timedsend_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_mq_timedreceive;
void syscalls::register_call_sys_mq_timedreceive(std::function<void(CPUState*, target_ulong, uint32_t, syscalls::string, uint32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_mq_timedreceive.push_back(callback);
}
struct sys_mq_timedreceive_calldata : public CallbackData {
target_ulong pc;
uint32_t mqdes;
syscalls::string msg_ptr;
uint32_t msg_len;
target_ulong msg_prio;
target_ulong abs_timeout;
};
static Callback_RC sys_mq_timedreceive_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_timedreceive_calldata* data = dynamic_cast<sys_mq_timedreceive_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_timedreceive_returned, env,data->pc,data->mqdes,data->msg_ptr.get_vaddr(),data->msg_len,data->msg_prio,data->abs_timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_timedreceive_callback(CPUState* env,target_ulong pc,uint32_t mqdes,syscalls::string msg_ptr,uint32_t msg_len,target_ulong msg_prio,target_ulong abs_timeout) {
for (auto x: internal_registered_callback_sys_mq_timedreceive){
    x(env,pc,mqdes,msg_ptr,msg_len,msg_prio,abs_timeout);
}
if (0 == ppp_on_sys_mq_timedreceive_returned_num_cb) return;
sys_mq_timedreceive_calldata* data = new sys_mq_timedreceive_calldata;
data->pc = pc;
data->mqdes = mqdes;
data->msg_ptr = msg_ptr;
data->msg_len = msg_len;
data->msg_prio = msg_prio;
data->abs_timeout = abs_timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_timedreceive_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_mq_notify;
void syscalls::register_call_sys_mq_notify(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_mq_notify.push_back(callback);
}
struct sys_mq_notify_calldata : public CallbackData {
target_ulong pc;
uint32_t mqdes;
target_ulong notification;
};
static Callback_RC sys_mq_notify_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_notify_calldata* data = dynamic_cast<sys_mq_notify_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_notify_returned, env,data->pc,data->mqdes,data->notification)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_notify_callback(CPUState* env,target_ulong pc,uint32_t mqdes,target_ulong notification) {
for (auto x: internal_registered_callback_sys_mq_notify){
    x(env,pc,mqdes,notification);
}
if (0 == ppp_on_sys_mq_notify_returned_num_cb) return;
sys_mq_notify_calldata* data = new sys_mq_notify_calldata;
data->pc = pc;
data->mqdes = mqdes;
data->notification = notification;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_notify_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_mq_getsetattr;
void syscalls::register_call_sys_mq_getsetattr(std::function<void(CPUState*, target_ulong, uint32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_mq_getsetattr.push_back(callback);
}
struct sys_mq_getsetattr_calldata : public CallbackData {
target_ulong pc;
uint32_t mqdes;
target_ulong mqstat;
target_ulong omqstat;
};
static Callback_RC sys_mq_getsetattr_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mq_getsetattr_calldata* data = dynamic_cast<sys_mq_getsetattr_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mq_getsetattr_returned, env,data->pc,data->mqdes,data->mqstat,data->omqstat)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mq_getsetattr_callback(CPUState* env,target_ulong pc,uint32_t mqdes,target_ulong mqstat,target_ulong omqstat) {
for (auto x: internal_registered_callback_sys_mq_getsetattr){
    x(env,pc,mqdes,mqstat,omqstat);
}
if (0 == ppp_on_sys_mq_getsetattr_returned_num_cb) return;
sys_mq_getsetattr_calldata* data = new sys_mq_getsetattr_calldata;
data->pc = pc;
data->mqdes = mqdes;
data->mqstat = mqstat;
data->omqstat = omqstat;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mq_getsetattr_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_waitid;
void syscalls::register_call_sys_waitid(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_waitid.push_back(callback);
}
struct sys_waitid_calldata : public CallbackData {
target_ulong pc;
int32_t which;
uint32_t pid;
target_ulong infop;
int32_t options;
target_ulong ru;
};
static Callback_RC sys_waitid_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_waitid_calldata* data = dynamic_cast<sys_waitid_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_waitid_returned, env,data->pc,data->which,data->pid,data->infop,data->options,data->ru)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_waitid_callback(CPUState* env,target_ulong pc,int32_t which,uint32_t pid,target_ulong infop,int32_t options,target_ulong ru) {
for (auto x: internal_registered_callback_sys_waitid){
    x(env,pc,which,pid,infop,options,ru);
}
if (0 == ppp_on_sys_waitid_returned_num_cb) return;
sys_waitid_calldata* data = new sys_waitid_calldata;
data->pc = pc;
data->which = which;
data->pid = pid;
data->infop = infop;
data->options = options;
data->ru = ru;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_waitid_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)>> internal_registered_callback_sys_socket;
void syscalls::register_call_sys_socket(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_socket.push_back(callback);
}
struct sys_socket_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
int32_t arg1;
int32_t arg2;
};
static Callback_RC sys_socket_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_socket_calldata* data = dynamic_cast<sys_socket_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_socket_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_socket_callback(CPUState* env,target_ulong pc,int32_t arg0,int32_t arg1,int32_t arg2) {
for (auto x: internal_registered_callback_sys_socket){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_socket_returned_num_cb) return;
sys_socket_calldata* data = new sys_socket_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_socket_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)>> internal_registered_callback_sys_bind;
void syscalls::register_call_sys_bind(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)> callback){
internal_registered_callback_sys_bind.push_back(callback);
}
struct sys_bind_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
int32_t arg2;
};
static Callback_RC sys_bind_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_bind_calldata* data = dynamic_cast<sys_bind_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_bind_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_bind_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,int32_t arg2) {
for (auto x: internal_registered_callback_sys_bind){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_bind_returned_num_cb) return;
sys_bind_calldata* data = new sys_bind_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_bind_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)>> internal_registered_callback_sys_connect;
void syscalls::register_call_sys_connect(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t)> callback){
internal_registered_callback_sys_connect.push_back(callback);
}
struct sys_connect_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
int32_t arg2;
};
static Callback_RC sys_connect_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_connect_calldata* data = dynamic_cast<sys_connect_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_connect_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_connect_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,int32_t arg2) {
for (auto x: internal_registered_callback_sys_connect){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_connect_returned_num_cb) return;
sys_connect_calldata* data = new sys_connect_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_connect_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_listen;
void syscalls::register_call_sys_listen(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_listen.push_back(callback);
}
struct sys_listen_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
int32_t arg1;
};
static Callback_RC sys_listen_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_listen_calldata* data = dynamic_cast<sys_listen_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_listen_returned, env,data->pc,data->arg0,data->arg1)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_listen_callback(CPUState* env,target_ulong pc,int32_t arg0,int32_t arg1) {
for (auto x: internal_registered_callback_sys_listen){
    x(env,pc,arg0,arg1);
}
if (0 == ppp_on_sys_listen_returned_num_cb) return;
sys_listen_calldata* data = new sys_listen_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_listen_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_accept;
void syscalls::register_call_sys_accept(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_accept.push_back(callback);
}
struct sys_accept_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
target_ulong arg2;
};
static Callback_RC sys_accept_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_accept_calldata* data = dynamic_cast<sys_accept_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_accept_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_accept_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,target_ulong arg2) {
for (auto x: internal_registered_callback_sys_accept){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_accept_returned_num_cb) return;
sys_accept_calldata* data = new sys_accept_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_accept_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_getsockname;
void syscalls::register_call_sys_getsockname(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getsockname.push_back(callback);
}
struct sys_getsockname_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
target_ulong arg2;
};
static Callback_RC sys_getsockname_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getsockname_calldata* data = dynamic_cast<sys_getsockname_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getsockname_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getsockname_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,target_ulong arg2) {
for (auto x: internal_registered_callback_sys_getsockname){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_getsockname_returned_num_cb) return;
sys_getsockname_calldata* data = new sys_getsockname_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getsockname_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_getpeername;
void syscalls::register_call_sys_getpeername(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getpeername.push_back(callback);
}
struct sys_getpeername_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
target_ulong arg2;
};
static Callback_RC sys_getpeername_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getpeername_calldata* data = dynamic_cast<sys_getpeername_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getpeername_returned, env,data->pc,data->arg0,data->arg1,data->arg2)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getpeername_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,target_ulong arg2) {
for (auto x: internal_registered_callback_sys_getpeername){
    x(env,pc,arg0,arg1,arg2);
}
if (0 == ppp_on_sys_getpeername_returned_num_cb) return;
sys_getpeername_calldata* data = new sys_getpeername_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getpeername_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, target_ulong)>> internal_registered_callback_sys_socketpair;
void syscalls::register_call_sys_socketpair(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_socketpair.push_back(callback);
}
struct sys_socketpair_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
int32_t arg1;
int32_t arg2;
target_ulong arg3;
};
static Callback_RC sys_socketpair_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_socketpair_calldata* data = dynamic_cast<sys_socketpair_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_socketpair_returned, env,data->pc,data->arg0,data->arg1,data->arg2,data->arg3)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_socketpair_callback(CPUState* env,target_ulong pc,int32_t arg0,int32_t arg1,int32_t arg2,target_ulong arg3) {
for (auto x: internal_registered_callback_sys_socketpair){
    x(env,pc,arg0,arg1,arg2,arg3);
}
if (0 == ppp_on_sys_socketpair_returned_num_cb) return;
sys_socketpair_calldata* data = new sys_socketpair_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
data->arg3 = arg3;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_socketpair_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_send;
void syscalls::register_call_sys_send(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_send.push_back(callback);
}
struct sys_send_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
uint32_t arg2;
uint32_t arg3;
};
static Callback_RC sys_send_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_send_calldata* data = dynamic_cast<sys_send_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_send_returned, env,data->pc,data->arg0,data->arg1,data->arg2,data->arg3)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_send_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,uint32_t arg2,uint32_t arg3) {
for (auto x: internal_registered_callback_sys_send){
    x(env,pc,arg0,arg1,arg2,arg3);
}
if (0 == ppp_on_sys_send_returned_num_cb) return;
sys_send_calldata* data = new sys_send_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
data->arg3 = arg3;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_send_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t, target_ulong, int32_t)>> internal_registered_callback_sys_sendto;
void syscalls::register_call_sys_sendto(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t, target_ulong, int32_t)> callback){
internal_registered_callback_sys_sendto.push_back(callback);
}
struct sys_sendto_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
uint32_t arg2;
uint32_t arg3;
target_ulong arg4;
int32_t arg5;
};
static Callback_RC sys_sendto_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sendto_calldata* data = dynamic_cast<sys_sendto_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sendto_returned, env,data->pc,data->arg0,data->arg1,data->arg2,data->arg3,data->arg4,data->arg5)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sendto_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,uint32_t arg2,uint32_t arg3,target_ulong arg4,int32_t arg5) {
for (auto x: internal_registered_callback_sys_sendto){
    x(env,pc,arg0,arg1,arg2,arg3,arg4,arg5);
}
if (0 == ppp_on_sys_sendto_returned_num_cb) return;
sys_sendto_calldata* data = new sys_sendto_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
data->arg3 = arg3;
data->arg4 = arg4;
data->arg5 = arg5;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sendto_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_recv;
void syscalls::register_call_sys_recv(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_recv.push_back(callback);
}
struct sys_recv_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
uint32_t arg2;
uint32_t arg3;
};
static Callback_RC sys_recv_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_recv_calldata* data = dynamic_cast<sys_recv_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_recv_returned, env,data->pc,data->arg0,data->arg1,data->arg2,data->arg3)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_recv_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,uint32_t arg2,uint32_t arg3) {
for (auto x: internal_registered_callback_sys_recv){
    x(env,pc,arg0,arg1,arg2,arg3);
}
if (0 == ppp_on_sys_recv_returned_num_cb) return;
sys_recv_calldata* data = new sys_recv_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
data->arg3 = arg3;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_recv_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_recvfrom;
void syscalls::register_call_sys_recvfrom(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_recvfrom.push_back(callback);
}
struct sys_recvfrom_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
target_ulong arg1;
uint32_t arg2;
uint32_t arg3;
target_ulong arg4;
target_ulong arg5;
};
static Callback_RC sys_recvfrom_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_recvfrom_calldata* data = dynamic_cast<sys_recvfrom_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_recvfrom_returned, env,data->pc,data->arg0,data->arg1,data->arg2,data->arg3,data->arg4,data->arg5)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_recvfrom_callback(CPUState* env,target_ulong pc,int32_t arg0,target_ulong arg1,uint32_t arg2,uint32_t arg3,target_ulong arg4,target_ulong arg5) {
for (auto x: internal_registered_callback_sys_recvfrom){
    x(env,pc,arg0,arg1,arg2,arg3,arg4,arg5);
}
if (0 == ppp_on_sys_recvfrom_returned_num_cb) return;
sys_recvfrom_calldata* data = new sys_recvfrom_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
data->arg2 = arg2;
data->arg3 = arg3;
data->arg4 = arg4;
data->arg5 = arg5;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_recvfrom_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_shutdown;
void syscalls::register_call_sys_shutdown(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_shutdown.push_back(callback);
}
struct sys_shutdown_calldata : public CallbackData {
target_ulong pc;
int32_t arg0;
int32_t arg1;
};
static Callback_RC sys_shutdown_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_shutdown_calldata* data = dynamic_cast<sys_shutdown_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_shutdown_returned, env,data->pc,data->arg0,data->arg1)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_shutdown_callback(CPUState* env,target_ulong pc,int32_t arg0,int32_t arg1) {
for (auto x: internal_registered_callback_sys_shutdown){
    x(env,pc,arg0,arg1);
}
if (0 == ppp_on_sys_shutdown_returned_num_cb) return;
sys_shutdown_calldata* data = new sys_shutdown_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_shutdown_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_setsockopt;
void syscalls::register_call_sys_setsockopt(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_setsockopt.push_back(callback);
}
struct sys_setsockopt_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
int32_t level;
int32_t optname;
syscalls::string optval;
int32_t optlen;
};
static Callback_RC sys_setsockopt_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_setsockopt_calldata* data = dynamic_cast<sys_setsockopt_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_setsockopt_returned, env,data->pc,data->fd,data->level,data->optname,data->optval.get_vaddr(),data->optlen)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_setsockopt_callback(CPUState* env,target_ulong pc,int32_t fd,int32_t level,int32_t optname,syscalls::string optval,int32_t optlen) {
for (auto x: internal_registered_callback_sys_setsockopt){
    x(env,pc,fd,level,optname,optval,optlen);
}
if (0 == ppp_on_sys_setsockopt_returned_num_cb) return;
sys_setsockopt_calldata* data = new sys_setsockopt_calldata;
data->pc = pc;
data->fd = fd;
data->level = level;
data->optname = optname;
data->optval = optval;
data->optlen = optlen;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_setsockopt_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, syscalls::string, target_ulong)>> internal_registered_callback_sys_getsockopt;
void syscalls::register_call_sys_getsockopt(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_getsockopt.push_back(callback);
}
struct sys_getsockopt_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
int32_t level;
int32_t optname;
syscalls::string optval;
target_ulong optlen;
};
static Callback_RC sys_getsockopt_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getsockopt_calldata* data = dynamic_cast<sys_getsockopt_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getsockopt_returned, env,data->pc,data->fd,data->level,data->optname,data->optval.get_vaddr(),data->optlen)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getsockopt_callback(CPUState* env,target_ulong pc,int32_t fd,int32_t level,int32_t optname,syscalls::string optval,target_ulong optlen) {
for (auto x: internal_registered_callback_sys_getsockopt){
    x(env,pc,fd,level,optname,optval,optlen);
}
if (0 == ppp_on_sys_getsockopt_returned_num_cb) return;
sys_getsockopt_calldata* data = new sys_getsockopt_calldata;
data->pc = pc;
data->fd = fd;
data->level = level;
data->optname = optname;
data->optval = optval;
data->optlen = optlen;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getsockopt_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_sendmsg;
void syscalls::register_call_sys_sendmsg(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_sendmsg.push_back(callback);
}
struct sys_sendmsg_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
target_ulong msg;
uint32_t flags;
};
static Callback_RC sys_sendmsg_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sendmsg_calldata* data = dynamic_cast<sys_sendmsg_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sendmsg_returned, env,data->pc,data->fd,data->msg,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sendmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags) {
for (auto x: internal_registered_callback_sys_sendmsg){
    x(env,pc,fd,msg,flags);
}
if (0 == ppp_on_sys_sendmsg_returned_num_cb) return;
sys_sendmsg_calldata* data = new sys_sendmsg_calldata;
data->pc = pc;
data->fd = fd;
data->msg = msg;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sendmsg_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_recvmsg;
void syscalls::register_call_sys_recvmsg(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_recvmsg.push_back(callback);
}
struct sys_recvmsg_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
target_ulong msg;
uint32_t flags;
};
static Callback_RC sys_recvmsg_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_recvmsg_calldata* data = dynamic_cast<sys_recvmsg_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_recvmsg_returned, env,data->pc,data->fd,data->msg,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_recvmsg_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong msg,uint32_t flags) {
for (auto x: internal_registered_callback_sys_recvmsg){
    x(env,pc,fd,msg,flags);
}
if (0 == ppp_on_sys_recvmsg_returned_num_cb) return;
sys_recvmsg_calldata* data = new sys_recvmsg_calldata;
data->pc = pc;
data->fd = fd;
data->msg = msg;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_recvmsg_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_semop;
void syscalls::register_call_sys_semop(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_semop.push_back(callback);
}
struct sys_semop_calldata : public CallbackData {
target_ulong pc;
int32_t semid;
target_ulong sops;
uint32_t nsops;
};
static Callback_RC sys_semop_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_semop_calldata* data = dynamic_cast<sys_semop_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_semop_returned, env,data->pc,data->semid,data->sops,data->nsops)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_semop_callback(CPUState* env,target_ulong pc,int32_t semid,target_ulong sops,uint32_t nsops) {
for (auto x: internal_registered_callback_sys_semop){
    x(env,pc,semid,sops,nsops);
}
if (0 == ppp_on_sys_semop_returned_num_cb) return;
sys_semop_calldata* data = new sys_semop_calldata;
data->pc = pc;
data->semid = semid;
data->sops = sops;
data->nsops = nsops;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_semop_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t, int32_t)>> internal_registered_callback_sys_semget;
void syscalls::register_call_sys_semget(std::function<void(CPUState*, target_ulong, uint32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_semget.push_back(callback);
}
struct sys_semget_calldata : public CallbackData {
target_ulong pc;
uint32_t key;
int32_t nsems;
int32_t semflg;
};
static Callback_RC sys_semget_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_semget_calldata* data = dynamic_cast<sys_semget_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_semget_returned, env,data->pc,data->key,data->nsems,data->semflg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_semget_callback(CPUState* env,target_ulong pc,uint32_t key,int32_t nsems,int32_t semflg) {
for (auto x: internal_registered_callback_sys_semget){
    x(env,pc,key,nsems,semflg);
}
if (0 == ppp_on_sys_semget_returned_num_cb) return;
sys_semget_calldata* data = new sys_semget_calldata;
data->pc = pc;
data->key = key;
data->nsems = nsems;
data->semflg = semflg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_semget_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, uint32_t)>> internal_registered_callback_sys_semctl;
void syscalls::register_call_sys_semctl(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t, uint32_t)> callback){
internal_registered_callback_sys_semctl.push_back(callback);
}
struct sys_semctl_calldata : public CallbackData {
target_ulong pc;
int32_t semid;
int32_t semnum;
int32_t cmd;
uint32_t arg;
};
static Callback_RC sys_semctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_semctl_calldata* data = dynamic_cast<sys_semctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_semctl_returned, env,data->pc,data->semid,data->semnum,data->cmd,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_semctl_callback(CPUState* env,target_ulong pc,int32_t semid,int32_t semnum,int32_t cmd,uint32_t arg) {
for (auto x: internal_registered_callback_sys_semctl){
    x(env,pc,semid,semnum,cmd,arg);
}
if (0 == ppp_on_sys_semctl_returned_num_cb) return;
sys_semctl_calldata* data = new sys_semctl_calldata;
data->pc = pc;
data->semid = semid;
data->semnum = semnum;
data->cmd = cmd;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_semctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_msgsnd;
void syscalls::register_call_sys_msgsnd(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_msgsnd.push_back(callback);
}
struct sys_msgsnd_calldata : public CallbackData {
target_ulong pc;
int32_t msqid;
target_ulong msgp;
uint32_t msgsz;
int32_t msgflg;
};
static Callback_RC sys_msgsnd_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_msgsnd_calldata* data = dynamic_cast<sys_msgsnd_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_msgsnd_returned, env,data->pc,data->msqid,data->msgp,data->msgsz,data->msgflg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_msgsnd_callback(CPUState* env,target_ulong pc,int32_t msqid,target_ulong msgp,uint32_t msgsz,int32_t msgflg) {
for (auto x: internal_registered_callback_sys_msgsnd){
    x(env,pc,msqid,msgp,msgsz,msgflg);
}
if (0 == ppp_on_sys_msgsnd_returned_num_cb) return;
sys_msgsnd_calldata* data = new sys_msgsnd_calldata;
data->pc = pc;
data->msqid = msqid;
data->msgp = msgp;
data->msgsz = msgsz;
data->msgflg = msgflg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_msgsnd_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t, int32_t)>> internal_registered_callback_sys_msgrcv;
void syscalls::register_call_sys_msgrcv(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_msgrcv.push_back(callback);
}
struct sys_msgrcv_calldata : public CallbackData {
target_ulong pc;
int32_t msqid;
target_ulong msgp;
uint32_t msgsz;
int32_t msgtyp;
int32_t msgflg;
};
static Callback_RC sys_msgrcv_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_msgrcv_calldata* data = dynamic_cast<sys_msgrcv_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_msgrcv_returned, env,data->pc,data->msqid,data->msgp,data->msgsz,data->msgtyp,data->msgflg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_msgrcv_callback(CPUState* env,target_ulong pc,int32_t msqid,target_ulong msgp,uint32_t msgsz,int32_t msgtyp,int32_t msgflg) {
for (auto x: internal_registered_callback_sys_msgrcv){
    x(env,pc,msqid,msgp,msgsz,msgtyp,msgflg);
}
if (0 == ppp_on_sys_msgrcv_returned_num_cb) return;
sys_msgrcv_calldata* data = new sys_msgrcv_calldata;
data->pc = pc;
data->msqid = msqid;
data->msgp = msgp;
data->msgsz = msgsz;
data->msgtyp = msgtyp;
data->msgflg = msgflg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_msgrcv_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_msgget;
void syscalls::register_call_sys_msgget(std::function<void(CPUState*, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_msgget.push_back(callback);
}
struct sys_msgget_calldata : public CallbackData {
target_ulong pc;
uint32_t key;
int32_t msgflg;
};
static Callback_RC sys_msgget_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_msgget_calldata* data = dynamic_cast<sys_msgget_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_msgget_returned, env,data->pc,data->key,data->msgflg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_msgget_callback(CPUState* env,target_ulong pc,uint32_t key,int32_t msgflg) {
for (auto x: internal_registered_callback_sys_msgget){
    x(env,pc,key,msgflg);
}
if (0 == ppp_on_sys_msgget_returned_num_cb) return;
sys_msgget_calldata* data = new sys_msgget_calldata;
data->pc = pc;
data->key = key;
data->msgflg = msgflg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_msgget_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)>> internal_registered_callback_sys_msgctl;
void syscalls::register_call_sys_msgctl(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_msgctl.push_back(callback);
}
struct sys_msgctl_calldata : public CallbackData {
target_ulong pc;
int32_t msqid;
int32_t cmd;
target_ulong buf;
};
static Callback_RC sys_msgctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_msgctl_calldata* data = dynamic_cast<sys_msgctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_msgctl_returned, env,data->pc,data->msqid,data->cmd,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_msgctl_callback(CPUState* env,target_ulong pc,int32_t msqid,int32_t cmd,target_ulong buf) {
for (auto x: internal_registered_callback_sys_msgctl){
    x(env,pc,msqid,cmd,buf);
}
if (0 == ppp_on_sys_msgctl_returned_num_cb) return;
sys_msgctl_calldata* data = new sys_msgctl_calldata;
data->pc = pc;
data->msqid = msqid;
data->cmd = cmd;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_msgctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_shmat;
void syscalls::register_call_sys_shmat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_shmat.push_back(callback);
}
struct sys_shmat_calldata : public CallbackData {
target_ulong pc;
int32_t shmid;
syscalls::string shmaddr;
int32_t shmflg;
};
static Callback_RC sys_shmat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_shmat_calldata* data = dynamic_cast<sys_shmat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_shmat_returned, env,data->pc,data->shmid,data->shmaddr.get_vaddr(),data->shmflg)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_shmat_callback(CPUState* env,target_ulong pc,int32_t shmid,syscalls::string shmaddr,int32_t shmflg) {
for (auto x: internal_registered_callback_sys_shmat){
    x(env,pc,shmid,shmaddr,shmflg);
}
if (0 == ppp_on_sys_shmat_returned_num_cb) return;
sys_shmat_calldata* data = new sys_shmat_calldata;
data->pc = pc;
data->shmid = shmid;
data->shmaddr = shmaddr;
data->shmflg = shmflg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_shmat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string)>> internal_registered_callback_sys_shmdt;
void syscalls::register_call_sys_shmdt(std::function<void(CPUState*, target_ulong, syscalls::string)> callback){
internal_registered_callback_sys_shmdt.push_back(callback);
}
struct sys_shmdt_calldata : public CallbackData {
target_ulong pc;
syscalls::string shmaddr;
};
static Callback_RC sys_shmdt_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_shmdt_calldata* data = dynamic_cast<sys_shmdt_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_shmdt_returned, env,data->pc,data->shmaddr.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_shmdt_callback(CPUState* env,target_ulong pc,syscalls::string shmaddr) {
for (auto x: internal_registered_callback_sys_shmdt){
    x(env,pc,shmaddr);
}
if (0 == ppp_on_sys_shmdt_returned_num_cb) return;
sys_shmdt_calldata* data = new sys_shmdt_calldata;
data->pc = pc;
data->shmaddr = shmaddr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_shmdt_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)>> internal_registered_callback_sys_shmget;
void syscalls::register_call_sys_shmget(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)> callback){
internal_registered_callback_sys_shmget.push_back(callback);
}
struct sys_shmget_calldata : public CallbackData {
target_ulong pc;
uint32_t key;
uint32_t size;
int32_t flag;
};
static Callback_RC sys_shmget_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_shmget_calldata* data = dynamic_cast<sys_shmget_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_shmget_returned, env,data->pc,data->key,data->size,data->flag)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_shmget_callback(CPUState* env,target_ulong pc,uint32_t key,uint32_t size,int32_t flag) {
for (auto x: internal_registered_callback_sys_shmget){
    x(env,pc,key,size,flag);
}
if (0 == ppp_on_sys_shmget_returned_num_cb) return;
sys_shmget_calldata* data = new sys_shmget_calldata;
data->pc = pc;
data->key = key;
data->size = size;
data->flag = flag;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_shmget_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)>> internal_registered_callback_sys_shmctl;
void syscalls::register_call_sys_shmctl(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong)> callback){
internal_registered_callback_sys_shmctl.push_back(callback);
}
struct sys_shmctl_calldata : public CallbackData {
target_ulong pc;
int32_t shmid;
int32_t cmd;
target_ulong buf;
};
static Callback_RC sys_shmctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_shmctl_calldata* data = dynamic_cast<sys_shmctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_shmctl_returned, env,data->pc,data->shmid,data->cmd,data->buf)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_shmctl_callback(CPUState* env,target_ulong pc,int32_t shmid,int32_t cmd,target_ulong buf) {
for (auto x: internal_registered_callback_sys_shmctl){
    x(env,pc,shmid,cmd,buf);
}
if (0 == ppp_on_sys_shmctl_returned_num_cb) return;
sys_shmctl_calldata* data = new sys_shmctl_calldata;
data->pc = pc;
data->shmid = shmid;
data->cmd = cmd;
data->buf = buf;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_shmctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_add_key;
void syscalls::register_call_sys_add_key(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_add_key.push_back(callback);
}
struct sys_add_key_calldata : public CallbackData {
target_ulong pc;
syscalls::string _type;
syscalls::string _description;
target_ulong _payload;
uint32_t plen;
uint32_t destringid;
};
static Callback_RC sys_add_key_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_add_key_calldata* data = dynamic_cast<sys_add_key_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_add_key_returned, env,data->pc,data->_type.get_vaddr(),data->_description.get_vaddr(),data->_payload,data->plen,data->destringid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_add_key_callback(CPUState* env,target_ulong pc,syscalls::string _type,syscalls::string _description,target_ulong _payload,uint32_t plen,uint32_t destringid) {
for (auto x: internal_registered_callback_sys_add_key){
    x(env,pc,_type,_description,_payload,plen,destringid);
}
if (0 == ppp_on_sys_add_key_returned_num_cb) return;
sys_add_key_calldata* data = new sys_add_key_calldata;
data->pc = pc;
data->_type = _type;
data->_description = _description;
data->_payload = _payload;
data->plen = plen;
data->destringid = destringid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_add_key_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, syscalls::string, uint32_t)>> internal_registered_callback_sys_request_key;
void syscalls::register_call_sys_request_key(std::function<void(CPUState*, target_ulong, syscalls::string, syscalls::string, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_request_key.push_back(callback);
}
struct sys_request_key_calldata : public CallbackData {
target_ulong pc;
syscalls::string _type;
syscalls::string _description;
syscalls::string _callout_info;
uint32_t destringid;
};
static Callback_RC sys_request_key_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_request_key_calldata* data = dynamic_cast<sys_request_key_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_request_key_returned, env,data->pc,data->_type.get_vaddr(),data->_description.get_vaddr(),data->_callout_info.get_vaddr(),data->destringid)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_request_key_callback(CPUState* env,target_ulong pc,syscalls::string _type,syscalls::string _description,syscalls::string _callout_info,uint32_t destringid) {
for (auto x: internal_registered_callback_sys_request_key){
    x(env,pc,_type,_description,_callout_info,destringid);
}
if (0 == ppp_on_sys_request_key_returned_num_cb) return;
sys_request_key_calldata* data = new sys_request_key_calldata;
data->pc = pc;
data->_type = _type;
data->_description = _description;
data->_callout_info = _callout_info;
data->destringid = destringid;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_request_key_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_keyctl;
void syscalls::register_call_sys_keyctl(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_keyctl.push_back(callback);
}
struct sys_keyctl_calldata : public CallbackData {
target_ulong pc;
int32_t cmd;
uint32_t arg2;
uint32_t arg3;
uint32_t arg4;
uint32_t arg5;
};
static Callback_RC sys_keyctl_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_keyctl_calldata* data = dynamic_cast<sys_keyctl_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_keyctl_returned, env,data->pc,data->cmd,data->arg2,data->arg3,data->arg4,data->arg5)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_keyctl_callback(CPUState* env,target_ulong pc,int32_t cmd,uint32_t arg2,uint32_t arg3,uint32_t arg4,uint32_t arg5) {
for (auto x: internal_registered_callback_sys_keyctl){
    x(env,pc,cmd,arg2,arg3,arg4,arg5);
}
if (0 == ppp_on_sys_keyctl_returned_num_cb) return;
sys_keyctl_calldata* data = new sys_keyctl_calldata;
data->pc = pc;
data->cmd = cmd;
data->arg2 = arg2;
data->arg3 = arg3;
data->arg4 = arg4;
data->arg5 = arg5;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_keyctl_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, target_ulong)>> internal_registered_callback_sys_semtimedop;
void syscalls::register_call_sys_semtimedop(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, target_ulong)> callback){
internal_registered_callback_sys_semtimedop.push_back(callback);
}
struct sys_semtimedop_calldata : public CallbackData {
target_ulong pc;
int32_t semid;
target_ulong sops;
uint32_t nsops;
target_ulong timeout;
};
static Callback_RC sys_semtimedop_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_semtimedop_calldata* data = dynamic_cast<sys_semtimedop_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_semtimedop_returned, env,data->pc,data->semid,data->sops,data->nsops,data->timeout)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_semtimedop_callback(CPUState* env,target_ulong pc,int32_t semid,target_ulong sops,uint32_t nsops,target_ulong timeout) {
for (auto x: internal_registered_callback_sys_semtimedop){
    x(env,pc,semid,sops,nsops,timeout);
}
if (0 == ppp_on_sys_semtimedop_returned_num_cb) return;
sys_semtimedop_calldata* data = new sys_semtimedop_calldata;
data->pc = pc;
data->semid = semid;
data->sops = sops;
data->nsops = nsops;
data->timeout = timeout;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_semtimedop_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)>> internal_registered_callback_sys_ioprio_set;
void syscalls::register_call_sys_ioprio_set(std::function<void(CPUState*, target_ulong, int32_t, int32_t, int32_t)> callback){
internal_registered_callback_sys_ioprio_set.push_back(callback);
}
struct sys_ioprio_set_calldata : public CallbackData {
target_ulong pc;
int32_t which;
int32_t who;
int32_t ioprio;
};
static Callback_RC sys_ioprio_set_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ioprio_set_calldata* data = dynamic_cast<sys_ioprio_set_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ioprio_set_returned, env,data->pc,data->which,data->who,data->ioprio)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ioprio_set_callback(CPUState* env,target_ulong pc,int32_t which,int32_t who,int32_t ioprio) {
for (auto x: internal_registered_callback_sys_ioprio_set){
    x(env,pc,which,who,ioprio);
}
if (0 == ppp_on_sys_ioprio_set_returned_num_cb) return;
sys_ioprio_set_calldata* data = new sys_ioprio_set_calldata;
data->pc = pc;
data->which = which;
data->who = who;
data->ioprio = ioprio;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ioprio_set_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_ioprio_get;
void syscalls::register_call_sys_ioprio_get(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_ioprio_get.push_back(callback);
}
struct sys_ioprio_get_calldata : public CallbackData {
target_ulong pc;
int32_t which;
int32_t who;
};
static Callback_RC sys_ioprio_get_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_ioprio_get_calldata* data = dynamic_cast<sys_ioprio_get_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_ioprio_get_returned, env,data->pc,data->which,data->who)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_ioprio_get_callback(CPUState* env,target_ulong pc,int32_t which,int32_t who) {
for (auto x: internal_registered_callback_sys_ioprio_get){
    x(env,pc,which,who);
}
if (0 == ppp_on_sys_ioprio_get_returned_num_cb) return;
sys_ioprio_get_calldata* data = new sys_ioprio_get_calldata;
data->pc = pc;
data->which = which;
data->who = who;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_ioprio_get_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_sys_inotify_init;
void syscalls::register_call_sys_inotify_init(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_sys_inotify_init.push_back(callback);
}
struct sys_inotify_init_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC sys_inotify_init_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_inotify_init_calldata* data = dynamic_cast<sys_inotify_init_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_inotify_init_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_inotify_init_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_sys_inotify_init){
    x(env,pc);
}
if (0 == ppp_on_sys_inotify_init_returned_num_cb) return;
sys_inotify_init_calldata* data = new sys_inotify_init_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_inotify_init_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)>> internal_registered_callback_sys_inotify_add_watch;
void syscalls::register_call_sys_inotify_add_watch(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_inotify_add_watch.push_back(callback);
}
struct sys_inotify_add_watch_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
syscalls::string path;
uint32_t mask;
};
static Callback_RC sys_inotify_add_watch_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_inotify_add_watch_calldata* data = dynamic_cast<sys_inotify_add_watch_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_inotify_add_watch_returned, env,data->pc,data->fd,data->path.get_vaddr(),data->mask)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_inotify_add_watch_callback(CPUState* env,target_ulong pc,int32_t fd,syscalls::string path,uint32_t mask) {
for (auto x: internal_registered_callback_sys_inotify_add_watch){
    x(env,pc,fd,path,mask);
}
if (0 == ppp_on_sys_inotify_add_watch_returned_num_cb) return;
sys_inotify_add_watch_calldata* data = new sys_inotify_add_watch_calldata;
data->pc = pc;
data->fd = fd;
data->path = path;
data->mask = mask;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_inotify_add_watch_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_inotify_rm_watch;
void syscalls::register_call_sys_inotify_rm_watch(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_inotify_rm_watch.push_back(callback);
}
struct sys_inotify_rm_watch_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
int32_t wd;
};
static Callback_RC sys_inotify_rm_watch_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_inotify_rm_watch_calldata* data = dynamic_cast<sys_inotify_rm_watch_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_inotify_rm_watch_returned, env,data->pc,data->fd,data->wd)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_inotify_rm_watch_callback(CPUState* env,target_ulong pc,int32_t fd,int32_t wd) {
for (auto x: internal_registered_callback_sys_inotify_rm_watch){
    x(env,pc,fd,wd);
}
if (0 == ppp_on_sys_inotify_rm_watch_returned_num_cb) return;
sys_inotify_rm_watch_calldata* data = new sys_inotify_rm_watch_calldata;
data->pc = pc;
data->fd = fd;
data->wd = wd;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_inotify_rm_watch_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_mbind;
void syscalls::register_call_sys_mbind(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_mbind.push_back(callback);
}
struct sys_mbind_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t len;
uint32_t mode;
target_ulong nmask;
uint32_t maxnode;
uint32_t flags;
};
static Callback_RC sys_mbind_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mbind_calldata* data = dynamic_cast<sys_mbind_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mbind_returned, env,data->pc,data->start,data->len,data->mode,data->nmask,data->maxnode,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mbind_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t len,uint32_t mode,target_ulong nmask,uint32_t maxnode,uint32_t flags) {
for (auto x: internal_registered_callback_sys_mbind){
    x(env,pc,start,len,mode,nmask,maxnode,flags);
}
if (0 == ppp_on_sys_mbind_returned_num_cb) return;
sys_mbind_calldata* data = new sys_mbind_calldata;
data->pc = pc;
data->start = start;
data->len = len;
data->mode = mode;
data->nmask = nmask;
data->maxnode = maxnode;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mbind_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_get_mempolicy;
void syscalls::register_call_sys_get_mempolicy(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_get_mempolicy.push_back(callback);
}
struct sys_get_mempolicy_calldata : public CallbackData {
target_ulong pc;
target_ulong policy;
target_ulong nmask;
uint32_t maxnode;
uint32_t addr;
uint32_t flags;
};
static Callback_RC sys_get_mempolicy_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_get_mempolicy_calldata* data = dynamic_cast<sys_get_mempolicy_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_get_mempolicy_returned, env,data->pc,data->policy,data->nmask,data->maxnode,data->addr,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_get_mempolicy_callback(CPUState* env,target_ulong pc,target_ulong policy,target_ulong nmask,uint32_t maxnode,uint32_t addr,uint32_t flags) {
for (auto x: internal_registered_callback_sys_get_mempolicy){
    x(env,pc,policy,nmask,maxnode,addr,flags);
}
if (0 == ppp_on_sys_get_mempolicy_returned_num_cb) return;
sys_get_mempolicy_calldata* data = new sys_get_mempolicy_calldata;
data->pc = pc;
data->policy = policy;
data->nmask = nmask;
data->maxnode = maxnode;
data->addr = addr;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_get_mempolicy_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_set_mempolicy;
void syscalls::register_call_sys_set_mempolicy(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_set_mempolicy.push_back(callback);
}
struct sys_set_mempolicy_calldata : public CallbackData {
target_ulong pc;
int32_t mode;
target_ulong nmask;
uint32_t maxnode;
};
static Callback_RC sys_set_mempolicy_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_set_mempolicy_calldata* data = dynamic_cast<sys_set_mempolicy_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_set_mempolicy_returned, env,data->pc,data->mode,data->nmask,data->maxnode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_set_mempolicy_callback(CPUState* env,target_ulong pc,int32_t mode,target_ulong nmask,uint32_t maxnode) {
for (auto x: internal_registered_callback_sys_set_mempolicy){
    x(env,pc,mode,nmask,maxnode);
}
if (0 == ppp_on_sys_set_mempolicy_returned_num_cb) return;
sys_set_mempolicy_calldata* data = new sys_set_mempolicy_calldata;
data->pc = pc;
data->mode = mode;
data->nmask = nmask;
data->maxnode = maxnode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_set_mempolicy_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, int32_t)>> internal_registered_callback_sys_openat;
void syscalls::register_call_sys_openat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, int32_t)> callback){
internal_registered_callback_sys_openat.push_back(callback);
}
struct sys_openat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
int32_t flags;
int32_t mode;
};
static Callback_RC sys_openat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_openat_calldata* data = dynamic_cast<sys_openat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_openat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->flags,data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_openat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,int32_t flags,int32_t mode) {
for (auto x: internal_registered_callback_sys_openat){
    x(env,pc,dfd,filename,flags,mode);
}
if (0 == ppp_on_sys_openat_returned_num_cb) return;
sys_openat_calldata* data = new sys_openat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->flags = flags;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_openat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_mkdirat;
void syscalls::register_call_sys_mkdirat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_mkdirat.push_back(callback);
}
struct sys_mkdirat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string pathname;
int32_t mode;
};
static Callback_RC sys_mkdirat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mkdirat_calldata* data = dynamic_cast<sys_mkdirat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mkdirat_returned, env,data->pc,data->dfd,data->pathname.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mkdirat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string pathname,int32_t mode) {
for (auto x: internal_registered_callback_sys_mkdirat){
    x(env,pc,dfd,pathname,mode);
}
if (0 == ppp_on_sys_mkdirat_returned_num_cb) return;
sys_mkdirat_calldata* data = new sys_mkdirat_calldata;
data->pc = pc;
data->dfd = dfd;
data->pathname = pathname;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mkdirat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, uint32_t)>> internal_registered_callback_sys_mknodat;
void syscalls::register_call_sys_mknodat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, uint32_t)> callback){
internal_registered_callback_sys_mknodat.push_back(callback);
}
struct sys_mknodat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
int32_t mode;
uint32_t dev;
};
static Callback_RC sys_mknodat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_mknodat_calldata* data = dynamic_cast<sys_mknodat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_mknodat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->mode,data->dev)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_mknodat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,int32_t mode,uint32_t dev) {
for (auto x: internal_registered_callback_sys_mknodat){
    x(env,pc,dfd,filename,mode,dev);
}
if (0 == ppp_on_sys_mknodat_returned_num_cb) return;
sys_mknodat_calldata* data = new sys_mknodat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->mode = mode;
data->dev = dev;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_mknodat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t, uint32_t, int32_t)>> internal_registered_callback_sys_fchownat;
void syscalls::register_call_sys_fchownat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t, uint32_t, int32_t)> callback){
internal_registered_callback_sys_fchownat.push_back(callback);
}
struct sys_fchownat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
uint32_t user;
uint32_t group;
int32_t flag;
};
static Callback_RC sys_fchownat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchownat_calldata* data = dynamic_cast<sys_fchownat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchownat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->user,data->group,data->flag)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchownat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,uint32_t user,uint32_t group,int32_t flag) {
for (auto x: internal_registered_callback_sys_fchownat){
    x(env,pc,dfd,filename,user,group,flag);
}
if (0 == ppp_on_sys_fchownat_returned_num_cb) return;
sys_fchownat_calldata* data = new sys_fchownat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->user = user;
data->group = group;
data->flag = flag;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchownat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong)>> internal_registered_callback_sys_futimesat;
void syscalls::register_call_sys_futimesat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong)> callback){
internal_registered_callback_sys_futimesat.push_back(callback);
}
struct sys_futimesat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
target_ulong utimes;
};
static Callback_RC sys_futimesat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_futimesat_calldata* data = dynamic_cast<sys_futimesat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_futimesat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->utimes)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_futimesat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,target_ulong utimes) {
for (auto x: internal_registered_callback_sys_futimesat){
    x(env,pc,dfd,filename,utimes);
}
if (0 == ppp_on_sys_futimesat_returned_num_cb) return;
sys_futimesat_calldata* data = new sys_futimesat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->utimes = utimes;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_futimesat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)>> internal_registered_callback_sys_fstatat64;
void syscalls::register_call_sys_fstatat64(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)> callback){
internal_registered_callback_sys_fstatat64.push_back(callback);
}
struct sys_fstatat64_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
target_ulong statbuf;
int32_t flag;
};
static Callback_RC sys_fstatat64_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fstatat64_calldata* data = dynamic_cast<sys_fstatat64_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fstatat64_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->statbuf,data->flag)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fstatat64_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,target_ulong statbuf,int32_t flag) {
for (auto x: internal_registered_callback_sys_fstatat64){
    x(env,pc,dfd,filename,statbuf,flag);
}
if (0 == ppp_on_sys_fstatat64_returned_num_cb) return;
sys_fstatat64_calldata* data = new sys_fstatat64_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->statbuf = statbuf;
data->flag = flag;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fstatat64_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_unlinkat;
void syscalls::register_call_sys_unlinkat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_unlinkat.push_back(callback);
}
struct sys_unlinkat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string pathname;
int32_t flag;
};
static Callback_RC sys_unlinkat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_unlinkat_calldata* data = dynamic_cast<sys_unlinkat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_unlinkat_returned, env,data->pc,data->dfd,data->pathname.get_vaddr(),data->flag)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_unlinkat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string pathname,int32_t flag) {
for (auto x: internal_registered_callback_sys_unlinkat){
    x(env,pc,dfd,pathname,flag);
}
if (0 == ppp_on_sys_unlinkat_returned_num_cb) return;
sys_unlinkat_calldata* data = new sys_unlinkat_calldata;
data->pc = pc;
data->dfd = dfd;
data->pathname = pathname;
data->flag = flag;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_unlinkat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, syscalls::string)>> internal_registered_callback_sys_renameat;
void syscalls::register_call_sys_renameat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, syscalls::string)> callback){
internal_registered_callback_sys_renameat.push_back(callback);
}
struct sys_renameat_calldata : public CallbackData {
target_ulong pc;
int32_t olddfd;
syscalls::string oldname;
int32_t newdfd;
syscalls::string newname;
};
static Callback_RC sys_renameat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_renameat_calldata* data = dynamic_cast<sys_renameat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_renameat_returned, env,data->pc,data->olddfd,data->oldname.get_vaddr(),data->newdfd,data->newname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_renameat_callback(CPUState* env,target_ulong pc,int32_t olddfd,syscalls::string oldname,int32_t newdfd,syscalls::string newname) {
for (auto x: internal_registered_callback_sys_renameat){
    x(env,pc,olddfd,oldname,newdfd,newname);
}
if (0 == ppp_on_sys_renameat_returned_num_cb) return;
sys_renameat_calldata* data = new sys_renameat_calldata;
data->pc = pc;
data->olddfd = olddfd;
data->oldname = oldname;
data->newdfd = newdfd;
data->newname = newname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_renameat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_linkat;
void syscalls::register_call_sys_linkat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_linkat.push_back(callback);
}
struct sys_linkat_calldata : public CallbackData {
target_ulong pc;
int32_t olddfd;
syscalls::string oldname;
int32_t newdfd;
syscalls::string newname;
int32_t flags;
};
static Callback_RC sys_linkat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_linkat_calldata* data = dynamic_cast<sys_linkat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_linkat_returned, env,data->pc,data->olddfd,data->oldname.get_vaddr(),data->newdfd,data->newname.get_vaddr(),data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_linkat_callback(CPUState* env,target_ulong pc,int32_t olddfd,syscalls::string oldname,int32_t newdfd,syscalls::string newname,int32_t flags) {
for (auto x: internal_registered_callback_sys_linkat){
    x(env,pc,olddfd,oldname,newdfd,newname,flags);
}
if (0 == ppp_on_sys_linkat_returned_num_cb) return;
sys_linkat_calldata* data = new sys_linkat_calldata;
data->pc = pc;
data->olddfd = olddfd;
data->oldname = oldname;
data->newdfd = newdfd;
data->newname = newname;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_linkat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, syscalls::string)>> internal_registered_callback_sys_symlinkat;
void syscalls::register_call_sys_symlinkat(std::function<void(CPUState*, target_ulong, syscalls::string, int32_t, syscalls::string)> callback){
internal_registered_callback_sys_symlinkat.push_back(callback);
}
struct sys_symlinkat_calldata : public CallbackData {
target_ulong pc;
syscalls::string oldname;
int32_t newdfd;
syscalls::string newname;
};
static Callback_RC sys_symlinkat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_symlinkat_calldata* data = dynamic_cast<sys_symlinkat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_symlinkat_returned, env,data->pc,data->oldname.get_vaddr(),data->newdfd,data->newname.get_vaddr())
return Callback_RC::NORMAL;
}
void syscalls::call_sys_symlinkat_callback(CPUState* env,target_ulong pc,syscalls::string oldname,int32_t newdfd,syscalls::string newname) {
for (auto x: internal_registered_callback_sys_symlinkat){
    x(env,pc,oldname,newdfd,newname);
}
if (0 == ppp_on_sys_symlinkat_returned_num_cb) return;
sys_symlinkat_calldata* data = new sys_symlinkat_calldata;
data->pc = pc;
data->oldname = oldname;
data->newdfd = newdfd;
data->newname = newname;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_symlinkat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)>> internal_registered_callback_sys_readlinkat;
void syscalls::register_call_sys_readlinkat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)> callback){
internal_registered_callback_sys_readlinkat.push_back(callback);
}
struct sys_readlinkat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string path;
target_ulong buf;
int32_t bufsiz;
};
static Callback_RC sys_readlinkat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_readlinkat_calldata* data = dynamic_cast<sys_readlinkat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_readlinkat_returned, env,data->pc,data->dfd,data->path.get_vaddr(),data->buf,data->bufsiz)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_readlinkat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string path,target_ulong buf,int32_t bufsiz) {
for (auto x: internal_registered_callback_sys_readlinkat){
    x(env,pc,dfd,path,buf,bufsiz);
}
if (0 == ppp_on_sys_readlinkat_returned_num_cb) return;
sys_readlinkat_calldata* data = new sys_readlinkat_calldata;
data->pc = pc;
data->dfd = dfd;
data->path = path;
data->buf = buf;
data->bufsiz = bufsiz;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_readlinkat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)>> internal_registered_callback_sys_fchmodat;
void syscalls::register_call_sys_fchmodat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, uint32_t)> callback){
internal_registered_callback_sys_fchmodat.push_back(callback);
}
struct sys_fchmodat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
uint32_t mode;
};
static Callback_RC sys_fchmodat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fchmodat_calldata* data = dynamic_cast<sys_fchmodat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fchmodat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fchmodat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,uint32_t mode) {
for (auto x: internal_registered_callback_sys_fchmodat){
    x(env,pc,dfd,filename,mode);
}
if (0 == ppp_on_sys_fchmodat_returned_num_cb) return;
sys_fchmodat_calldata* data = new sys_fchmodat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fchmodat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)>> internal_registered_callback_sys_faccessat;
void syscalls::register_call_sys_faccessat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, int32_t)> callback){
internal_registered_callback_sys_faccessat.push_back(callback);
}
struct sys_faccessat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
int32_t mode;
};
static Callback_RC sys_faccessat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_faccessat_calldata* data = dynamic_cast<sys_faccessat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_faccessat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->mode)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_faccessat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,int32_t mode) {
for (auto x: internal_registered_callback_sys_faccessat){
    x(env,pc,dfd,filename,mode);
}
if (0 == ppp_on_sys_faccessat_returned_num_cb) return;
sys_faccessat_calldata* data = new sys_faccessat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->mode = mode;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_faccessat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_unshare;
void syscalls::register_call_sys_unshare(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_unshare.push_back(callback);
}
struct sys_unshare_calldata : public CallbackData {
target_ulong pc;
uint32_t unshare_flags;
};
static Callback_RC sys_unshare_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_unshare_calldata* data = dynamic_cast<sys_unshare_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_unshare_returned, env,data->pc,data->unshare_flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_unshare_callback(CPUState* env,target_ulong pc,uint32_t unshare_flags) {
for (auto x: internal_registered_callback_sys_unshare){
    x(env,pc,unshare_flags);
}
if (0 == ppp_on_sys_unshare_returned_num_cb) return;
sys_unshare_calldata* data = new sys_unshare_calldata;
data->pc = pc;
data->unshare_flags = unshare_flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_unshare_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)>> internal_registered_callback_sys_set_robust_list;
void syscalls::register_call_sys_set_robust_list(std::function<void(CPUState*, target_ulong, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_set_robust_list.push_back(callback);
}
struct sys_set_robust_list_calldata : public CallbackData {
target_ulong pc;
target_ulong head;
uint32_t len;
};
static Callback_RC sys_set_robust_list_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_set_robust_list_calldata* data = dynamic_cast<sys_set_robust_list_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_set_robust_list_returned, env,data->pc,data->head,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_set_robust_list_callback(CPUState* env,target_ulong pc,target_ulong head,uint32_t len) {
for (auto x: internal_registered_callback_sys_set_robust_list){
    x(env,pc,head,len);
}
if (0 == ppp_on_sys_set_robust_list_returned_num_cb) return;
sys_set_robust_list_calldata* data = new sys_set_robust_list_calldata;
data->pc = pc;
data->head = head;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_set_robust_list_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_get_robust_list;
void syscalls::register_call_sys_get_robust_list(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_get_robust_list.push_back(callback);
}
struct sys_get_robust_list_calldata : public CallbackData {
target_ulong pc;
int32_t pid;
target_ulong head_ptr;
target_ulong len_ptr;
};
static Callback_RC sys_get_robust_list_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_get_robust_list_calldata* data = dynamic_cast<sys_get_robust_list_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_get_robust_list_returned, env,data->pc,data->pid,data->head_ptr,data->len_ptr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_get_robust_list_callback(CPUState* env,target_ulong pc,int32_t pid,target_ulong head_ptr,target_ulong len_ptr) {
for (auto x: internal_registered_callback_sys_get_robust_list){
    x(env,pc,pid,head_ptr,len_ptr);
}
if (0 == ppp_on_sys_get_robust_list_returned_num_cb) return;
sys_get_robust_list_calldata* data = new sys_get_robust_list_calldata;
data->pc = pc;
data->pid = pid;
data->head_ptr = head_ptr;
data->len_ptr = len_ptr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_get_robust_list_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_splice;
void syscalls::register_call_sys_splice(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_splice.push_back(callback);
}
struct sys_splice_calldata : public CallbackData {
target_ulong pc;
int32_t fd_in;
target_ulong off_in;
int32_t fd_out;
target_ulong off_out;
uint32_t len;
uint32_t flags;
};
static Callback_RC sys_splice_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_splice_calldata* data = dynamic_cast<sys_splice_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_splice_returned, env,data->pc,data->fd_in,data->off_in,data->fd_out,data->off_out,data->len,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_splice_callback(CPUState* env,target_ulong pc,int32_t fd_in,target_ulong off_in,int32_t fd_out,target_ulong off_out,uint32_t len,uint32_t flags) {
for (auto x: internal_registered_callback_sys_splice){
    x(env,pc,fd_in,off_in,fd_out,off_out,len,flags);
}
if (0 == ppp_on_sys_splice_returned_num_cb) return;
sys_splice_calldata* data = new sys_splice_calldata;
data->pc = pc;
data->fd_in = fd_in;
data->off_in = off_in;
data->fd_out = fd_out;
data->off_out = off_out;
data->len = len;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_splice_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint64_t, uint64_t)>> internal_registered_callback_sys_sync_file_range2;
void syscalls::register_call_sys_sync_file_range2(std::function<void(CPUState*, target_ulong, int32_t, uint32_t, uint64_t, uint64_t)> callback){
internal_registered_callback_sys_sync_file_range2.push_back(callback);
}
struct sys_sync_file_range2_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
uint32_t flags;
uint64_t offset;
uint64_t nbytes;
};
static Callback_RC sys_sync_file_range2_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_sync_file_range2_calldata* data = dynamic_cast<sys_sync_file_range2_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_sync_file_range2_returned, env,data->pc,data->fd,data->flags,data->offset,data->nbytes)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_sync_file_range2_callback(CPUState* env,target_ulong pc,int32_t fd,uint32_t flags,uint64_t offset,uint64_t nbytes) {
for (auto x: internal_registered_callback_sys_sync_file_range2){
    x(env,pc,fd,flags,offset,nbytes);
}
if (0 == ppp_on_sys_sync_file_range2_returned_num_cb) return;
sys_sync_file_range2_calldata* data = new sys_sync_file_range2_calldata;
data->pc = pc;
data->fd = fd;
data->flags = flags;
data->offset = offset;
data->nbytes = nbytes;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_sync_file_range2_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint32_t, uint32_t)>> internal_registered_callback_sys_tee;
void syscalls::register_call_sys_tee(std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_tee.push_back(callback);
}
struct sys_tee_calldata : public CallbackData {
target_ulong pc;
int32_t fdin;
int32_t fdout;
uint32_t len;
uint32_t flags;
};
static Callback_RC sys_tee_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_tee_calldata* data = dynamic_cast<sys_tee_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_tee_returned, env,data->pc,data->fdin,data->fdout,data->len,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_tee_callback(CPUState* env,target_ulong pc,int32_t fdin,int32_t fdout,uint32_t len,uint32_t flags) {
for (auto x: internal_registered_callback_sys_tee){
    x(env,pc,fdin,fdout,len,flags);
}
if (0 == ppp_on_sys_tee_returned_num_cb) return;
sys_tee_calldata* data = new sys_tee_calldata;
data->pc = pc;
data->fdin = fdin;
data->fdout = fdout;
data->len = len;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_tee_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)>> internal_registered_callback_sys_vmsplice;
void syscalls::register_call_sys_vmsplice(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, uint32_t)> callback){
internal_registered_callback_sys_vmsplice.push_back(callback);
}
struct sys_vmsplice_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
target_ulong iov;
uint32_t nr_segs;
uint32_t flags;
};
static Callback_RC sys_vmsplice_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_vmsplice_calldata* data = dynamic_cast<sys_vmsplice_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_vmsplice_returned, env,data->pc,data->fd,data->iov,data->nr_segs,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_vmsplice_callback(CPUState* env,target_ulong pc,int32_t fd,target_ulong iov,uint32_t nr_segs,uint32_t flags) {
for (auto x: internal_registered_callback_sys_vmsplice){
    x(env,pc,fd,iov,nr_segs,flags);
}
if (0 == ppp_on_sys_vmsplice_returned_num_cb) return;
sys_vmsplice_calldata* data = new sys_vmsplice_calldata;
data->pc = pc;
data->fd = fd;
data->iov = iov;
data->nr_segs = nr_segs;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_vmsplice_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, target_ulong, target_ulong, int32_t)>> internal_registered_callback_sys_move_pages;
void syscalls::register_call_sys_move_pages(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, target_ulong, target_ulong, int32_t)> callback){
internal_registered_callback_sys_move_pages.push_back(callback);
}
struct sys_move_pages_calldata : public CallbackData {
target_ulong pc;
uint32_t pid;
uint32_t nr_pages;
target_ulong pages;
target_ulong nodes;
target_ulong status;
int32_t flags;
};
static Callback_RC sys_move_pages_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_move_pages_calldata* data = dynamic_cast<sys_move_pages_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_move_pages_returned, env,data->pc,data->pid,data->nr_pages,data->pages,data->nodes,data->status,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_move_pages_callback(CPUState* env,target_ulong pc,uint32_t pid,uint32_t nr_pages,target_ulong pages,target_ulong nodes,target_ulong status,int32_t flags) {
for (auto x: internal_registered_callback_sys_move_pages){
    x(env,pc,pid,nr_pages,pages,nodes,status,flags);
}
if (0 == ppp_on_sys_move_pages_returned_num_cb) return;
sys_move_pages_calldata* data = new sys_move_pages_calldata;
data->pc = pc;
data->pid = pid;
data->nr_pages = nr_pages;
data->pages = pages;
data->nodes = nodes;
data->status = status;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_move_pages_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)>> internal_registered_callback_sys_getcpu;
void syscalls::register_call_sys_getcpu(std::function<void(CPUState*, target_ulong, target_ulong, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_getcpu.push_back(callback);
}
struct sys_getcpu_calldata : public CallbackData {
target_ulong pc;
target_ulong cpu;
target_ulong node;
target_ulong cache;
};
static Callback_RC sys_getcpu_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_getcpu_calldata* data = dynamic_cast<sys_getcpu_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_getcpu_returned, env,data->pc,data->cpu,data->node,data->cache)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_getcpu_callback(CPUState* env,target_ulong pc,target_ulong cpu,target_ulong node,target_ulong cache) {
for (auto x: internal_registered_callback_sys_getcpu){
    x(env,pc,cpu,node,cache);
}
if (0 == ppp_on_sys_getcpu_returned_num_cb) return;
sys_getcpu_calldata* data = new sys_getcpu_calldata;
data->pc = pc;
data->cpu = cpu;
data->node = node;
data->cache = cache;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_getcpu_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_kexec_load;
void syscalls::register_call_sys_kexec_load(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_kexec_load.push_back(callback);
}
struct sys_kexec_load_calldata : public CallbackData {
target_ulong pc;
uint32_t entry;
uint32_t nr_segments;
target_ulong segments;
uint32_t flags;
};
static Callback_RC sys_kexec_load_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_kexec_load_calldata* data = dynamic_cast<sys_kexec_load_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_kexec_load_returned, env,data->pc,data->entry,data->nr_segments,data->segments,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_kexec_load_callback(CPUState* env,target_ulong pc,uint32_t entry,uint32_t nr_segments,target_ulong segments,uint32_t flags) {
for (auto x: internal_registered_callback_sys_kexec_load){
    x(env,pc,entry,nr_segments,segments,flags);
}
if (0 == ppp_on_sys_kexec_load_returned_num_cb) return;
sys_kexec_load_calldata* data = new sys_kexec_load_calldata;
data->pc = pc;
data->entry = entry;
data->nr_segments = nr_segments;
data->segments = segments;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_kexec_load_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)>> internal_registered_callback_sys_utimensat;
void syscalls::register_call_sys_utimensat(std::function<void(CPUState*, target_ulong, int32_t, syscalls::string, target_ulong, int32_t)> callback){
internal_registered_callback_sys_utimensat.push_back(callback);
}
struct sys_utimensat_calldata : public CallbackData {
target_ulong pc;
int32_t dfd;
syscalls::string filename;
target_ulong utimes;
int32_t flags;
};
static Callback_RC sys_utimensat_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_utimensat_calldata* data = dynamic_cast<sys_utimensat_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_utimensat_returned, env,data->pc,data->dfd,data->filename.get_vaddr(),data->utimes,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_utimensat_callback(CPUState* env,target_ulong pc,int32_t dfd,syscalls::string filename,target_ulong utimes,int32_t flags) {
for (auto x: internal_registered_callback_sys_utimensat){
    x(env,pc,dfd,filename,utimes,flags);
}
if (0 == ppp_on_sys_utimensat_returned_num_cb) return;
sys_utimensat_calldata* data = new sys_utimensat_calldata;
data->pc = pc;
data->dfd = dfd;
data->filename = filename;
data->utimes = utimes;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_utimensat_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)>> internal_registered_callback_sys_signalfd;
void syscalls::register_call_sys_signalfd(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_signalfd.push_back(callback);
}
struct sys_signalfd_calldata : public CallbackData {
target_ulong pc;
int32_t ufd;
target_ulong user_mask;
uint32_t sizemask;
};
static Callback_RC sys_signalfd_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_signalfd_calldata* data = dynamic_cast<sys_signalfd_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_signalfd_returned, env,data->pc,data->ufd,data->user_mask,data->sizemask)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_signalfd_callback(CPUState* env,target_ulong pc,int32_t ufd,target_ulong user_mask,uint32_t sizemask) {
for (auto x: internal_registered_callback_sys_signalfd){
    x(env,pc,ufd,user_mask,sizemask);
}
if (0 == ppp_on_sys_signalfd_returned_num_cb) return;
sys_signalfd_calldata* data = new sys_signalfd_calldata;
data->pc = pc;
data->ufd = ufd;
data->user_mask = user_mask;
data->sizemask = sizemask;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_signalfd_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t)>> internal_registered_callback_sys_timerfd_create;
void syscalls::register_call_sys_timerfd_create(std::function<void(CPUState*, target_ulong, int32_t, int32_t)> callback){
internal_registered_callback_sys_timerfd_create.push_back(callback);
}
struct sys_timerfd_create_calldata : public CallbackData {
target_ulong pc;
int32_t clockid;
int32_t flags;
};
static Callback_RC sys_timerfd_create_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timerfd_create_calldata* data = dynamic_cast<sys_timerfd_create_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timerfd_create_returned, env,data->pc,data->clockid,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timerfd_create_callback(CPUState* env,target_ulong pc,int32_t clockid,int32_t flags) {
for (auto x: internal_registered_callback_sys_timerfd_create){
    x(env,pc,clockid,flags);
}
if (0 == ppp_on_sys_timerfd_create_returned_num_cb) return;
sys_timerfd_create_calldata* data = new sys_timerfd_create_calldata;
data->pc = pc;
data->clockid = clockid;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timerfd_create_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_sys_eventfd;
void syscalls::register_call_sys_eventfd(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_sys_eventfd.push_back(callback);
}
struct sys_eventfd_calldata : public CallbackData {
target_ulong pc;
uint32_t count;
};
static Callback_RC sys_eventfd_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_eventfd_calldata* data = dynamic_cast<sys_eventfd_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_eventfd_returned, env,data->pc,data->count)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_eventfd_callback(CPUState* env,target_ulong pc,uint32_t count) {
for (auto x: internal_registered_callback_sys_eventfd){
    x(env,pc,count);
}
if (0 == ppp_on_sys_eventfd_returned_num_cb) return;
sys_eventfd_calldata* data = new sys_eventfd_calldata;
data->pc = pc;
data->count = count;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_eventfd_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint64_t, uint64_t)>> internal_registered_callback_sys_fallocate;
void syscalls::register_call_sys_fallocate(std::function<void(CPUState*, target_ulong, int32_t, int32_t, uint64_t, uint64_t)> callback){
internal_registered_callback_sys_fallocate.push_back(callback);
}
struct sys_fallocate_calldata : public CallbackData {
target_ulong pc;
int32_t fd;
int32_t mode;
uint64_t offset;
uint64_t len;
};
static Callback_RC sys_fallocate_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_fallocate_calldata* data = dynamic_cast<sys_fallocate_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_fallocate_returned, env,data->pc,data->fd,data->mode,data->offset,data->len)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_fallocate_callback(CPUState* env,target_ulong pc,int32_t fd,int32_t mode,uint64_t offset,uint64_t len) {
for (auto x: internal_registered_callback_sys_fallocate){
    x(env,pc,fd,mode,offset,len);
}
if (0 == ppp_on_sys_fallocate_returned_num_cb) return;
sys_fallocate_calldata* data = new sys_fallocate_calldata;
data->pc = pc;
data->fd = fd;
data->mode = mode;
data->offset = offset;
data->len = len;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_fallocate_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, target_ulong)>> internal_registered_callback_sys_timerfd_settime;
void syscalls::register_call_sys_timerfd_settime(std::function<void(CPUState*, target_ulong, int32_t, int32_t, target_ulong, target_ulong)> callback){
internal_registered_callback_sys_timerfd_settime.push_back(callback);
}
struct sys_timerfd_settime_calldata : public CallbackData {
target_ulong pc;
int32_t ufd;
int32_t flags;
target_ulong utmr;
target_ulong otmr;
};
static Callback_RC sys_timerfd_settime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timerfd_settime_calldata* data = dynamic_cast<sys_timerfd_settime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timerfd_settime_returned, env,data->pc,data->ufd,data->flags,data->utmr,data->otmr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timerfd_settime_callback(CPUState* env,target_ulong pc,int32_t ufd,int32_t flags,target_ulong utmr,target_ulong otmr) {
for (auto x: internal_registered_callback_sys_timerfd_settime){
    x(env,pc,ufd,flags,utmr,otmr);
}
if (0 == ppp_on_sys_timerfd_settime_returned_num_cb) return;
sys_timerfd_settime_calldata* data = new sys_timerfd_settime_calldata;
data->pc = pc;
data->ufd = ufd;
data->flags = flags;
data->utmr = utmr;
data->otmr = otmr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timerfd_settime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong)>> internal_registered_callback_sys_timerfd_gettime;
void syscalls::register_call_sys_timerfd_gettime(std::function<void(CPUState*, target_ulong, int32_t, target_ulong)> callback){
internal_registered_callback_sys_timerfd_gettime.push_back(callback);
}
struct sys_timerfd_gettime_calldata : public CallbackData {
target_ulong pc;
int32_t ufd;
target_ulong otmr;
};
static Callback_RC sys_timerfd_gettime_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_timerfd_gettime_calldata* data = dynamic_cast<sys_timerfd_gettime_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_timerfd_gettime_returned, env,data->pc,data->ufd,data->otmr)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_timerfd_gettime_callback(CPUState* env,target_ulong pc,int32_t ufd,target_ulong otmr) {
for (auto x: internal_registered_callback_sys_timerfd_gettime){
    x(env,pc,ufd,otmr);
}
if (0 == ppp_on_sys_timerfd_gettime_returned_num_cb) return;
sys_timerfd_gettime_calldata* data = new sys_timerfd_gettime_calldata;
data->pc = pc;
data->ufd = ufd;
data->otmr = otmr;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_timerfd_gettime_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_signalfd4;
void syscalls::register_call_sys_signalfd4(std::function<void(CPUState*, target_ulong, int32_t, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_signalfd4.push_back(callback);
}
struct sys_signalfd4_calldata : public CallbackData {
target_ulong pc;
int32_t ufd;
target_ulong user_mask;
uint32_t sizemask;
int32_t flags;
};
static Callback_RC sys_signalfd4_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_signalfd4_calldata* data = dynamic_cast<sys_signalfd4_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_signalfd4_returned, env,data->pc,data->ufd,data->user_mask,data->sizemask,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_signalfd4_callback(CPUState* env,target_ulong pc,int32_t ufd,target_ulong user_mask,uint32_t sizemask,int32_t flags) {
for (auto x: internal_registered_callback_sys_signalfd4){
    x(env,pc,ufd,user_mask,sizemask,flags);
}
if (0 == ppp_on_sys_signalfd4_returned_num_cb) return;
sys_signalfd4_calldata* data = new sys_signalfd4_calldata;
data->pc = pc;
data->ufd = ufd;
data->user_mask = user_mask;
data->sizemask = sizemask;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_signalfd4_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, int32_t)>> internal_registered_callback_sys_eventfd2;
void syscalls::register_call_sys_eventfd2(std::function<void(CPUState*, target_ulong, uint32_t, int32_t)> callback){
internal_registered_callback_sys_eventfd2.push_back(callback);
}
struct sys_eventfd2_calldata : public CallbackData {
target_ulong pc;
uint32_t count;
int32_t flags;
};
static Callback_RC sys_eventfd2_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_eventfd2_calldata* data = dynamic_cast<sys_eventfd2_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_eventfd2_returned, env,data->pc,data->count,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_eventfd2_callback(CPUState* env,target_ulong pc,uint32_t count,int32_t flags) {
for (auto x: internal_registered_callback_sys_eventfd2){
    x(env,pc,count,flags);
}
if (0 == ppp_on_sys_eventfd2_returned_num_cb) return;
sys_eventfd2_calldata* data = new sys_eventfd2_calldata;
data->pc = pc;
data->count = count;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_eventfd2_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_epoll_create1;
void syscalls::register_call_sys_epoll_create1(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_epoll_create1.push_back(callback);
}
struct sys_epoll_create1_calldata : public CallbackData {
target_ulong pc;
int32_t flags;
};
static Callback_RC sys_epoll_create1_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_epoll_create1_calldata* data = dynamic_cast<sys_epoll_create1_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_epoll_create1_returned, env,data->pc,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_epoll_create1_callback(CPUState* env,target_ulong pc,int32_t flags) {
for (auto x: internal_registered_callback_sys_epoll_create1){
    x(env,pc,flags);
}
if (0 == ppp_on_sys_epoll_create1_returned_num_cb) return;
sys_epoll_create1_calldata* data = new sys_epoll_create1_calldata;
data->pc = pc;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_epoll_create1_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)>> internal_registered_callback_sys_dup3;
void syscalls::register_call_sys_dup3(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, int32_t)> callback){
internal_registered_callback_sys_dup3.push_back(callback);
}
struct sys_dup3_calldata : public CallbackData {
target_ulong pc;
uint32_t oldfd;
uint32_t newfd;
int32_t flags;
};
static Callback_RC sys_dup3_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_dup3_calldata* data = dynamic_cast<sys_dup3_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_dup3_returned, env,data->pc,data->oldfd,data->newfd,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_dup3_callback(CPUState* env,target_ulong pc,uint32_t oldfd,uint32_t newfd,int32_t flags) {
for (auto x: internal_registered_callback_sys_dup3){
    x(env,pc,oldfd,newfd,flags);
}
if (0 == ppp_on_sys_dup3_returned_num_cb) return;
sys_dup3_calldata* data = new sys_dup3_calldata;
data->pc = pc;
data->oldfd = oldfd;
data->newfd = newfd;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_dup3_returned));}
std::vector<std::function<void(CPUState*, target_ulong, target_ulong, int32_t)>> internal_registered_callback_sys_pipe2;
void syscalls::register_call_sys_pipe2(std::function<void(CPUState*, target_ulong, target_ulong, int32_t)> callback){
internal_registered_callback_sys_pipe2.push_back(callback);
}
struct sys_pipe2_calldata : public CallbackData {
target_ulong pc;
target_ulong arg0;
int32_t arg1;
};
static Callback_RC sys_pipe2_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_pipe2_calldata* data = dynamic_cast<sys_pipe2_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_pipe2_returned, env,data->pc,data->arg0,data->arg1)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_pipe2_callback(CPUState* env,target_ulong pc,target_ulong arg0,int32_t arg1) {
for (auto x: internal_registered_callback_sys_pipe2){
    x(env,pc,arg0,arg1);
}
if (0 == ppp_on_sys_pipe2_returned_num_cb) return;
sys_pipe2_calldata* data = new sys_pipe2_calldata;
data->pc = pc;
data->arg0 = arg0;
data->arg1 = arg1;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_pipe2_returned));}
std::vector<std::function<void(CPUState*, target_ulong, int32_t)>> internal_registered_callback_sys_inotify_init1;
void syscalls::register_call_sys_inotify_init1(std::function<void(CPUState*, target_ulong, int32_t)> callback){
internal_registered_callback_sys_inotify_init1.push_back(callback);
}
struct sys_inotify_init1_calldata : public CallbackData {
target_ulong pc;
int32_t flags;
};
static Callback_RC sys_inotify_init1_returned(CallbackData* opaque, CPUState* env, target_asid asid){
sys_inotify_init1_calldata* data = dynamic_cast<sys_inotify_init1_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_sys_inotify_init1_returned, env,data->pc,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_sys_inotify_init1_callback(CPUState* env,target_ulong pc,int32_t flags) {
for (auto x: internal_registered_callback_sys_inotify_init1){
    x(env,pc,flags);
}
if (0 == ppp_on_sys_inotify_init1_returned_num_cb) return;
sys_inotify_init1_calldata* data = new sys_inotify_init1_calldata;
data->pc = pc;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, sys_inotify_init1_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_ARM_breakpoint;
void syscalls::register_call_ARM_breakpoint(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_ARM_breakpoint.push_back(callback);
}
struct ARM_breakpoint_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC ARM_breakpoint_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_breakpoint_calldata* data = dynamic_cast<ARM_breakpoint_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_breakpoint_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_breakpoint_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_ARM_breakpoint){
    x(env,pc);
}
if (0 == ppp_on_ARM_breakpoint_returned_num_cb) return;
ARM_breakpoint_calldata* data = new ARM_breakpoint_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_breakpoint_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)>> internal_registered_callback_ARM_cacheflush;
void syscalls::register_call_ARM_cacheflush(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, uint32_t)> callback){
internal_registered_callback_ARM_cacheflush.push_back(callback);
}
struct ARM_cacheflush_calldata : public CallbackData {
target_ulong pc;
uint32_t start;
uint32_t end;
uint32_t flags;
};
static Callback_RC ARM_cacheflush_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_cacheflush_calldata* data = dynamic_cast<ARM_cacheflush_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_cacheflush_returned, env,data->pc,data->start,data->end,data->flags)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_cacheflush_callback(CPUState* env,target_ulong pc,uint32_t start,uint32_t end,uint32_t flags) {
for (auto x: internal_registered_callback_ARM_cacheflush){
    x(env,pc,start,end,flags);
}
if (0 == ppp_on_ARM_cacheflush_returned_num_cb) return;
ARM_cacheflush_calldata* data = new ARM_cacheflush_calldata;
data->pc = pc;
data->start = start;
data->end = end;
data->flags = flags;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_cacheflush_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_ARM_user26_mode;
void syscalls::register_call_ARM_user26_mode(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_ARM_user26_mode.push_back(callback);
}
struct ARM_user26_mode_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC ARM_user26_mode_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_user26_mode_calldata* data = dynamic_cast<ARM_user26_mode_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_user26_mode_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_user26_mode_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_ARM_user26_mode){
    x(env,pc);
}
if (0 == ppp_on_ARM_user26_mode_returned_num_cb) return;
ARM_user26_mode_calldata* data = new ARM_user26_mode_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_user26_mode_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_ARM_usr32_mode;
void syscalls::register_call_ARM_usr32_mode(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_ARM_usr32_mode.push_back(callback);
}
struct ARM_usr32_mode_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC ARM_usr32_mode_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_usr32_mode_calldata* data = dynamic_cast<ARM_usr32_mode_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_usr32_mode_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_usr32_mode_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_ARM_usr32_mode){
    x(env,pc);
}
if (0 == ppp_on_ARM_usr32_mode_returned_num_cb) return;
ARM_usr32_mode_calldata* data = new ARM_usr32_mode_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_usr32_mode_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t)>> internal_registered_callback_ARM_set_tls;
void syscalls::register_call_ARM_set_tls(std::function<void(CPUState*, target_ulong, uint32_t)> callback){
internal_registered_callback_ARM_set_tls.push_back(callback);
}
struct ARM_set_tls_calldata : public CallbackData {
target_ulong pc;
uint32_t arg;
};
static Callback_RC ARM_set_tls_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_set_tls_calldata* data = dynamic_cast<ARM_set_tls_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_set_tls_returned, env,data->pc,data->arg)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_set_tls_callback(CPUState* env,target_ulong pc,uint32_t arg) {
for (auto x: internal_registered_callback_ARM_set_tls){
    x(env,pc,arg);
}
if (0 == ppp_on_ARM_set_tls_returned_num_cb) return;
ARM_set_tls_calldata* data = new ARM_set_tls_calldata;
data->pc = pc;
data->arg = arg;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_set_tls_returned));}
std::vector<std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)>> internal_registered_callback_ARM_cmpxchg;
void syscalls::register_call_ARM_cmpxchg(std::function<void(CPUState*, target_ulong, uint32_t, uint32_t, target_ulong)> callback){
internal_registered_callback_ARM_cmpxchg.push_back(callback);
}
struct ARM_cmpxchg_calldata : public CallbackData {
target_ulong pc;
uint32_t val;
uint32_t src;
target_ulong dest;
};
static Callback_RC ARM_cmpxchg_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_cmpxchg_calldata* data = dynamic_cast<ARM_cmpxchg_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_cmpxchg_returned, env,data->pc,data->val,data->src,data->dest)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_cmpxchg_callback(CPUState* env,target_ulong pc,uint32_t val,uint32_t src,target_ulong dest) {
for (auto x: internal_registered_callback_ARM_cmpxchg){
    x(env,pc,val,src,dest);
}
if (0 == ppp_on_ARM_cmpxchg_returned_num_cb) return;
ARM_cmpxchg_calldata* data = new ARM_cmpxchg_calldata;
data->pc = pc;
data->val = val;
data->src = src;
data->dest = dest;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_cmpxchg_returned));}
std::vector<std::function<void(CPUState*, target_ulong)>> internal_registered_callback_ARM_null_segfault;
void syscalls::register_call_ARM_null_segfault(std::function<void(CPUState*, target_ulong)> callback){
internal_registered_callback_ARM_null_segfault.push_back(callback);
}
struct ARM_null_segfault_calldata : public CallbackData {
target_ulong pc;
};
static Callback_RC ARM_null_segfault_returned(CallbackData* opaque, CPUState* env, target_asid asid){
ARM_null_segfault_calldata* data = dynamic_cast<ARM_null_segfault_calldata*>(opaque);
if(!data) {fprintf(stderr,"oops\n"); return Callback_RC::ERROR;}
PPP_RUN_CB(on_ARM_null_segfault_returned, env,data->pc)
return Callback_RC::NORMAL;
}
void syscalls::call_ARM_null_segfault_callback(CPUState* env,target_ulong pc) {
for (auto x: internal_registered_callback_ARM_null_segfault){
    x(env,pc);
}
if (0 == ppp_on_ARM_null_segfault_returned_num_cb) return;
ARM_null_segfault_calldata* data = new ARM_null_segfault_calldata;
data->pc = pc;
appendReturnPoint(ReturnPoint(calc_retaddr(env, pc), get_asid(env, pc), data, ARM_null_segfault_returned));}

#endif

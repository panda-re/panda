/* PANDABEGINCOMMENT
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <string>
#include <unordered_map>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "read_info.h"
#include "filemon.h"

#include<iostream>
#include<fstream>

using namespace std;

ofstream outf;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

  PPP_PROT_REG_CB(on_file_read);
  PPP_PROT_REG_CB(on_file_write);
  
}

PPP_CB_BOILERPLATE(on_file_read);
PPP_CB_BOILERPLATE(on_file_write);


// Read metadata, specifically the file position upon entry.
using FilePosition = uint64_t;
static std::unordered_map<FileKey, FilePosition> read_positions;
static std::unordered_map<FileKey, FilePosition> write_positions;

static bool verbose = false;
static bool pread_bits_64 = false;

static int serialnum = 0;
static uint8_t *read_buffer = NULL;
static int read_buffer_len;
static uint8_t *write_buffer = NULL;
static int write_buffer_len, write_buffer_count;



// Helper function that only prints if the verbose flag is set.
void verbose_printf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  if (verbose) {
    vprintf(fmt, args);
  }
  va_end(args);
}


// A normalized read_enter function. Called by both Linux and Windows
// specific calls.
void read_enter(const std::string &filename, uint64_t file_id,
                uint64_t position)
{

  // Construct the read key and record the associated start position of the
  // read.
  FileKey key;
  OsiProc *proc = get_current_process(first_cpu);
  OsiThread *thr = get_current_thread(first_cpu);
  key.process_id = proc ? proc->pid : 0;
  key.thread_id = thr->tid;
  key.file_id = file_id;
  read_positions[key] = position;
  
  verbose_printf("filemon read_enter: filename=\"%s\" pid=%lu "
		 "tid=%lu fid=%lu\n",
		 filename.c_str(), key.process_id, thr->tid, file_id);

  char info[128];
  sprintf (info, "read-enter-%d-%d-%d-%s-%d", (int) key.process_id, (int) thr->tid, (int) file_id, proc->name, serialnum);
  outf << info << " \"" << filename << "\"\n";
  
  //  outf << key.process_id << " " << thr->tid << " " << file_id << " " << proc->name;
  //  outf << " read_enter \"" << filename << "\"\n";
  
  free_osiproc(proc);
  free_osithread(thr);
}


// A normaled read_return function. Called by both Linux and Windows read return
// implementations.
void read_return(uint64_t file_id, uint64_t bytes_read,
                 target_ulong buffer_addr)
{
  // Construct our read key (a tuple of PID, TID, and file ID (handle or
  // descriptor).
  FileKey key;
  OsiProc *proc = get_current_process(first_cpu);
  OsiThread *thr = get_current_thread(first_cpu);
  key.process_id = proc ? proc->pid : 0;
  key.thread_id = thr->tid;
  key.file_id = file_id;
  
  // If we haven't seen a read with this key, don't do anything.
  if (read_positions.find(key) == read_positions.end()) {
    verbose_printf("filemon read_return: don't know about read, "
		   "discarding (pid=%lu tid=%lu fid=%lu)\n",
		   key.process_id, thr->tid, file_id);
    return;
  }
  
  verbose_printf("filemon read_return: read return detected "
		 "(pid=%lu tid=%lu fid=%lu)\n",
		 key.process_id, thr->tid, file_id);

  char info[128];
  sprintf (info, "read-return-%d-%d-%d-%s-%d", (int) key.process_id, (int) thr->tid, (int) file_id, proc->name, serialnum);
  outf << info << "\n";
  
  if (read_buffer == NULL) {
    read_buffer_len = 2*bytes_read;
    read_buffer = (uint8_t *) malloc(read_buffer_len);
  }
  if (read_buffer_len < bytes_read) {
    read_buffer_len = 2*bytes_read;
    read_buffer = (uint8_t *) realloc(read_buffer, read_buffer_len);
  }

  panda_virtual_memory_read(first_cpu, buffer_addr, read_buffer, bytes_read);
  FILE *fp = fopen(info, "w");
  fwrite(read_buffer, 1, bytes_read, fp);
  fclose(fp);
  serialnum ++;  
  
  // We've seen the read, lookup the position of the file at the time of the
  // read enter.
  uint64_t read_start_pos = read_positions[key];
  
  PPP_RUN_CB(on_file_read, key.process_id, thr->tid, file_id, bytes_read, buffer_addr, read_start_pos);
  
  // We've handled the read for this pid, tid, and file id. We have to see
  // another read enter before we can be here again for the same pid, tid and
  // file id key.
  read_positions.erase(key);
  
  free_osiproc(proc);
  free_osithread(thr);
}

#ifdef TARGET_I386
// Handle a Windows read enter. Extract the filename and offset of the file
// handle and call the normalized read enter.
void windows_read_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle,
                        uint32_t Event, uint32_t UserApcRoutine,
                        uint32_t UserApcContext, uint32_t IoStatusBlock,
                        uint32_t Buffer, uint32_t BufferLength,
                        uint32_t ByteOffset, uint32_t Key)
{
  char *filename = get_handle_name(cpu, get_current_proc(cpu), FileHandle);
  std::string ob_path = filename;
  // Check if the file handle is absolute, if not we need to make it absolute.
  if (filename[0] != '\\') {
    char *cwd = get_cwd(cpu);
    ob_path = cwd;
    // If the cwd doesn't have a slash, add it.
    if (ob_path.back() != '\\') {
      ob_path += "\\";
    }
    ob_path += filename;
    g_free(cwd);
  }
  verbose_printf("filemon windows object path: %s\n", ob_path.c_str());
  int64_t pos = get_file_handle_pos(cpu, get_current_proc(cpu), FileHandle);
  read_enter(ob_path, FileHandle, pos);
  g_free(filename);
}

// From DDK
typedef uint32_t NTSTATUS;
const NTSTATUS STATUS_SUCCESS = 0x00000000;
const NTSTATUS STATUS_PENDING = 0x00000103;

// Handle a Windows read return. Gets the number of bytes read from the file and
// calls the normalized read return.
void windows_read_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle,
                         uint32_t Event, uint32_t UserApcRoutine,
                         uint32_t UserApcContext, uint32_t IoStatusBlock,
                         uint32_t Buffer, uint32_t BufferLength,
                         uint32_t ByteOffset, uint32_t Key)
{
  struct {
    union {
      NTSTATUS status;
      uint32_t pointer;
    };
    uint32_t information;
  } io_status_block;
  if (panda_virtual_memory_read(cpu, IoStatusBlock,
				(uint8_t *)&io_status_block,
				sizeof(io_status_block)) == -1) {
    printf("failed to read number of bytes read\n");
    return;
  }
  
  if (io_status_block.status == STATUS_PENDING) {
    printf(
	   "filemon read return: detected async read return, ignoring\n");
  } else if (io_status_block.status == STATUS_SUCCESS) {
    read_return(FileHandle, io_status_block.information, Buffer);
  } else {
    printf("filemon windows_read_return: detected read failure, "
	   "ignoring\n");
  }
}
#endif

// Handle a Linux read enter. Extract the filename and offset of the file
// descriptor and call the normalized read enter.
void linux_read_enter(CPUState *cpu, target_ulong pc, uint32_t fd,
                      uint32_t buffer, uint32_t count)
{
  OsiProc *proc = get_current_process(cpu);
  // The filename in Linux should always be absolute.
  char *filename = osi_linux_fd_to_filename(cpu, proc, fd);
  uint64_t pos = osi_linux_fd_to_pos(cpu, proc, fd);
  read_enter(filename, fd, pos);
  g_free(filename);
  free_osiproc(proc);
}


// Handle a Linux pread enter. Extract the filename and use the position passed
// to pread to call the normalized read enter.
void linux_pread_enter(CPUState *cpu, target_ulong pc, uint32_t fd,
                       uint32_t buf, uint32_t count, uint64_t pos)
{
  OsiProc *proc = get_current_process(cpu);
  // The filename in Linux should always be absolute.
  char *filename = osi_linux_fd_to_filename(cpu, proc, fd);
  if (pread_bits_64) {
    read_enter(filename, fd, pos);
  } else {
    read_enter(filename, fd, (int32_t)pos);
  }
  g_free(filename);
  free_osiproc(proc);
}

// Handle a Linux read return. Extract the number of bytes read from EAX and
// call the normalized read return.
void linux_read_return(CPUState *cpu, target_ulong pc, uint32_t fd,
                       uint32_t buffer, uint32_t count)
{
  ssize_t actually_read = 0;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    // EAX has the number of bytes read.
  actually_read = env->regs[R_EAX];
#else
  fprintf(
	  stderr,
	  "WARNING: filemon only supports 32-bit x86 Linux and Windows.\n");
  return;
#endif
  if (actually_read != -1) {
    read_return(fd, actually_read, buffer);
  } else {
    printf("filemon linux_read_return: detected read failure, "
	   "ignoring.\n");
  }
}


void linux_pread_return(CPUState *cpu, target_ulong pc, uint32_t fd,
                        uint32_t buf, uint32_t count, uint64_t pos)
{
  // Just call the regular linux read return
  linux_read_return(cpu, pc, fd, buf, count);
}



// A normalized write_enter function.
// Called by both Linux and Windows specific calls.
void write_enter(const std::string &filename, uint64_t file_id,
                uint64_t position)
{

  // Construct the write key and record the associated start position of the
  // read.
  FileKey key;
  OsiProc *proc = get_current_process(first_cpu);
  OsiThread *thr = get_current_thread(first_cpu);
  key.process_id = proc ? proc->pid : 0;
  key.thread_id = thr->tid;
  key.file_id = file_id;
  write_positions[key] = position;
  
  verbose_printf("filemon write_enter: filename=\"%s\" pid=%lu "
		 "tid=%lu fid=%lu\n",
		 filename.c_str(), key.process_id, thr->tid, file_id);

  char info[128];
  sprintf (info, "write-enter-%d-%d-%d-%s-%d", (int) key.process_id, (int) thr->tid, (int) file_id, proc->name, serialnum);
  outf << info << " \"" << filename << "\"\n";

  FILE *fp = fopen(info, "w");
  fwrite(write_buffer, 1, write_buffer_count, fp);
  fclose(fp);
  serialnum ++;


  free_osiproc(proc);
  free_osithread(thr);
}


// A normaled write_return function. Called by both Linux and Windows write return
// implementations.
void write_return(uint64_t file_id, uint64_t bytes_write,
                 target_ulong buffer_addr)
{
  // Construct our write key (a tuple of PID, TID, and file ID (handle or
  // descriptor).
  FileKey key;
  OsiProc *proc = get_current_process(first_cpu);
  OsiThread *thr = get_current_thread(first_cpu);
  key.process_id = proc ? proc->pid : 0;
  key.thread_id = thr->tid;
  key.file_id = file_id;
  
  // If we haven't seen a write with this key, don't do anything.
  if (write_positions.find(key) == write_positions.end()) {
    verbose_printf("filemon write_return: don't know about write, "
		   "discarding (pid=%lu tid=%lu fid=%lu)\n",
		   key.process_id, thr->tid, file_id);
    return;
  }
  
  verbose_printf("filemon write_return: write return detected "
		 "(pid=%lu tid=%lu fid=%lu)\n",
		 key.process_id, thr->tid, file_id);
  

  char info[128];
  sprintf (info, "write-return-%d-%d-%d-%s-%d", (int) key.process_id, (int) thr->tid, (int) file_id, proc->name, serialnum);
  outf << info << "\n";
  
  // We've seen the write, lookup the position of the file at the time of the
  // write enter.
  uint64_t write_start_pos = write_positions[key];
  
  PPP_RUN_CB(on_file_write, key.process_id, thr->tid, file_id, bytes_write, buffer_addr, write_start_pos);
  
  // We've handled the write for this pid, tid, and file id. We have to see
  // another write enter before we can be here again for the same pid, tid and
  // file id key.
  write_positions.erase(key);
  
  free_osiproc(proc);
  free_osithread(thr);
}

void linux_write_enter(CPUState *cpu, target_ulong pc, uint32_t fd,
		       uint32_t buffer, uint32_t count)
{
  OsiProc *proc = get_current_process(cpu);
  // The filename in Linux should always be absolute.
  char *filename = osi_linux_fd_to_filename(cpu, proc, fd);
  uint64_t pos = osi_linux_fd_to_pos(cpu, proc, fd);
  write_enter(filename, fd, pos);

  if (write_buffer == NULL) {
    write_buffer_len = 2*count;
    write_buffer = (uint8_t *) malloc(write_buffer_len);
  }
  if (write_buffer_len < count) {
    write_buffer_len = 2*count;
    write_buffer = (uint8_t *) realloc(write_buffer, write_buffer_len);
  }
  
  panda_virtual_memory_read(first_cpu, buffer, write_buffer, count);
  write_buffer_count = count;

  g_free(filename);
  free_osiproc(proc);
}


void linux_write_return(CPUState *cpu, target_ulong pc, uint32_t fd,
			uint32_t buffer, uint32_t count)
{
  ssize_t actually_written = 0;
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  // EAX has the number of bytes written.
  actually_written = env->regs[R_EAX];
#else
  fprintf(
	  stderr,
	  "WARNING: filemon only supports 32-bit x86 Linux and Windows.\n");
  return;
#endif
  if (actually_written != -1) {
    write_return(fd, actually_written, buffer);
  } else {
    printf("filemon linux_write_return: detected write failure, "
	   "ignoring.\n");
  }
}

void windows_write_enter(CPUState* cpu, target_ulong pc, uint32_t FileHandle,
			 uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext,
			 uint32_t IoStatusBlock, uint32_t Buffer, uint32_t Length,
			 uint32_t ByteOffset, uint32_t Key)
{
  char *filename = get_handle_name(cpu, get_current_proc(cpu), FileHandle);
  std::string ob_path = filename;
  // Check if the file handle is absolute, if not we need to make it absolute.
  if (filename[0] != '\\') {
    char *cwd = get_cwd(cpu);
    ob_path = cwd;
    // If the cwd doesn't have a slash, add it.
    if (ob_path.back() != '\\') {
      ob_path += "\\";
    }
    ob_path += filename;
    g_free(cwd);
  }
  verbose_printf("filemon windows object path: %s\n", ob_path.c_str());
  int64_t pos = get_file_handle_pos(cpu, get_current_proc(cpu), FileHandle);
  write_enter(ob_path, FileHandle, pos);
  g_free(filename);
}

void windows_write_return(CPUState* cpu, target_ulong pc, uint32_t FileHandle,
			  uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext,
			  uint32_t IoStatusBlock, uint32_t Buffer, uint32_t Length,
			  uint32_t ByteOffset, uint32_t Key)
{
  struct {
    union {
      NTSTATUS status;
      uint32_t pointer;
    };
    uint32_t information;
  } io_status_block;
  if (panda_virtual_memory_read(cpu, IoStatusBlock,
				(uint8_t *)&io_status_block,
				sizeof(io_status_block)) == -1) {
    printf("failed to read number of bytes written\n");
    return;
  }

  if (io_status_block.status == STATUS_PENDING) {
    printf(
	   "filemon write return: detected async write return, ignoring\n");
    } else if (io_status_block.status == STATUS_SUCCESS) {
        write_return(FileHandle, io_status_block.information, Buffer);
    } else {
        printf("filemon windows_write_return: detected write failure, "
               "ignoring\n");
    }
}



bool init_plugin(void *self)
{
  // Parse arguments for filemon
  panda_arg_list *args = panda_get_args("filemon");
  verbose = panda_parse_bool_opt(args, "verbose", "enable verbose output");
  pread_bits_64 =
    panda_parse_bool_opt(args, "pread_bits_64",
                             "Assume the offset passed to pread is a signed "
			 "64-bit integer (Linux specific)");
  
    // Setup dependencies
  panda_require("syscalls2");
  assert(init_syscalls2_api());
  panda_require("osi");
  assert(init_osi_api());
  
  // OS specific setup
  switch (panda_os_familyno) {
  case OS_WINDOWS: {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    verbose_printf("filemon: setting up Windows file read detection\n");
    PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
    PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);
    PPP_REG_CB("syscalls2", on_NtWriteFile_enter, windows_write_enter);
    PPP_REG_CB("syscalls2", on_NtWriteFile_return, windows_write_return);
    
    panda_require("wintrospection");
    assert(init_wintrospection_api());
#else
    fprintf(stderr, "ERROR: Windows is only supported on x86 (32-bit)\n");
    return false;
#endif
  } break;
  case OS_LINUX: {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    verbose_printf("filemon: setting up Linux file read detection\n");
    PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
    PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
    PPP_REG_CB("syscalls2", on_sys_pread64_enter, linux_pread_enter);
    PPP_REG_CB("syscalls2", on_sys_pread64_return, linux_pread_return);
    PPP_REG_CB("syscalls2", on_sys_write_enter, linux_write_enter);
    PPP_REG_CB("syscalls2", on_sys_write_return, linux_write_enter);
    
    panda_require("osi_linux");
    assert(init_osi_linux_api());
#else
    fprintf(stderr, "ERROR: Linux is only supported on x86 (32-bit)\n");
    return false;
#endif
  } break;
  default: {
    fprintf(stderr, "filemon2: OS not supported!\n");
    return false;
  } break;
  }

  outf.open("filemon");
  outf << "pid\ttid\tfid\tprocname\t...\n";

  return true;
}

void uninit_plugin(void *self) {
  outf.close();
}

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

#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

#include "osi_linux/osi_linux_ext.h"

#include "taint2/taint2_ext.h"

#include "read_info.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
}

// Plugin arguments.
static std::string target_filename;
static uint64_t min_byte_pos;
static uint64_t max_byte_pos;
static bool positional;
static uint32_t static_label;

// Read metadata, specifically the file position upon entry.
using FilePosition = uint64_t;
static std::unordered_map<ReadKey, FilePosition> read_positions;

bool is_match(const std::string &filename)
{
    size_t pos = filename.rfind(target_filename);
    return pos != std::string::npos &&
           filename.substr(pos).size() == target_filename.size();
}

void read_enter(const std::string &filename, uint64_t file_id,
                uint64_t position)
{
    // 1. Check if the filename matches else return
    if (!is_match(filename)) {
        return;
    }

    // 2. Enable Taint.
    taint2_enable_taint();

    // 3. Insert read key <-> position pair into map.
    ReadKey key;
    OsiProc *proc = get_current_process(first_cpu);
    OsiThread *thr = get_current_thread(first_cpu);
    key.process_id = proc ? proc->pid : 0;
    key.thread_id = thr->tid;
    key.file_id = file_id;
    read_positions[key] = position;

    free_osiproc_g(proc);
    free_osithread_g(thr);

    printf("enter thread id = %u\n", (uint32_t)key.thread_id);
}

void read_return(uint64_t file_id, uint64_t bytes_read,
                 target_ulong buffer_addr)
{
    ReadKey key;
    OsiProc *proc = get_current_process(first_cpu);
    OsiThread *thr = get_current_thread(first_cpu);
    key.process_id = proc ? proc->pid : 0;
    key.thread_id = thr->tid;
    key.file_id = file_id;
    if (read_positions.find(key) == read_positions.end()) {
        return;
    }
    int64_t read_start_pos = read_positions[key];
    for (int i = 0; i < bytes_read; i++) {
        int64_t curpos = read_start_pos + i;
        if (min_byte_pos <= curpos && curpos <= max_byte_pos) {
            printf("applying label\n");
            hwaddr shadow_addr = panda_virt_to_phys(first_cpu, buffer_addr + i);

            if (positional) {
                taint2_label_ram(shadow_addr, curpos);
            } else {
                taint2_label_ram(shadow_addr, static_label);
            }
        }
    }
    free_osiproc_g(proc);
    free_osithread_g(thr);

    printf("return thread id = %u\n", (uint32_t)key.thread_id);
}

#ifdef TARGET_I386
void windows_read_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle,
                        uint32_t Event, uint32_t UserApcRoutine,
                        uint32_t UserApcContext, uint32_t IoStatusBlock,
                        uint32_t Buffer, uint32_t BufferLength,
                        uint32_t ByteOffset, uint32_t Key)
{
    char *filename = get_handle_name(cpu, get_current_proc(cpu), FileHandle);
    int64_t pos = get_file_handle_pos(cpu, get_current_proc(cpu), FileHandle);
    read_enter(filename, FileHandle, pos);
    g_free(filename);
}

void windows_read_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle,
                         uint32_t Event, uint32_t UserApcRoutine,
                         uint32_t UserApcContext, uint32_t IoStatusBlock,
                         uint32_t Buffer, uint32_t BufferLength,
                         uint32_t ByteOffset, uint32_t Key)
{
    uint32_t bytes_read;
    if (panda_virtual_memory_read(cpu, IoStatusBlock + 4,
                                  (uint8_t *)&bytes_read,
                                  sizeof(bytes_read)) == -1) {
        printf("failed to read number of bytes read\n");
        return;
    }
    read_return(FileHandle, bytes_read, Buffer);
}
#endif

void linux_read_enter(CPUState *cpu, target_ulong pc, uint32_t fd,
                      uint32_t buffer, uint32_t count)
{
    OsiProc *proc = get_current_process(cpu);
    char *filename = osi_linux_fd_to_filename(cpu, proc, fd);
    uint64_t pos = osi_linux_fd_to_pos(cpu, proc, fd);
    read_enter(filename, fd, pos);
    free(filename);
    free_osiproc_g(proc);
}

void linux_read_return(CPUState *cpu, target_ulong pc, uint32_t fd,
                       uint32_t buffer, uint32_t count)
{
    uint32_t actually_read = 0;
#ifdef TARGET_I386
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    actually_read = env->regs[R_EAX];
#endif
    // Again, assume that the thread ID is the same as PID in Linux.
    read_return(fd, actually_read, buffer);
}

bool init_plugin(void *self)
{
    panda_require("syscalls2");
    assert(init_syscalls2_api());

    panda_require("osi");
    assert(init_osi_api());

    panda_require("taint2");
    assert(init_taint2_api());

    switch (panda_os_familyno) {
    case OS_WINDOWS: {
#ifdef TARGET_I386
        PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
        PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);

        panda_require("wintrospection");
        assert(init_wintrospection_api());
#endif
    } break;
    case OS_LINUX: {
#ifndef TARGET_PPC
        PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
        PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);

        panda_require("osi_linux");
        assert(init_osi_linux_api());
#endif
    } break;
    default: {
        printf("file_taint2: OS not supported!\n");
        return 1;
    } break;
    }

    panda_arg_list *args = panda_get_args("file_taint");
    target_filename =
        panda_parse_string_req(args, "filename", "name of file to taint");
    min_byte_pos = panda_parse_uint64_opt(
        args, "min_byte_pos", 0,
        "minimum byte offset within the file to start tainting");
    max_byte_pos =
        panda_parse_uint64_opt(args, "max_byte_pos", UINT64_MAX,
                               "max byte offset within the file to taint");
    positional = panda_parse_bool_opt(args, "pos",
                                      "enable or disable positional labels");
    static_label = panda_parse_uint32_opt(
        args, "label", 0xF11E, "the label to use (for non-positional labels)");

    return true;
}

void uninit_plugin(void *self) { }

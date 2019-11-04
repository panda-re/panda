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

#include "syscalls2/syscalls_ext_typedefs.h"
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
static std::string target_filename = "";
// All bytes in the file can be tainted by default.
static uint64_t min_byte_pos = 0;
static uint64_t max_byte_pos = UINT64_MAX;
static uint64_t max_byte_count = 1000000;
static bool positional = false;
static uint32_t static_label = 0xF11E;
static bool verbose = false;
static bool pread_bits_64 = false;

// Number of bytes tainted, used for the max_byte_count option.
static uint64_t tainted_byte_count = 0;

// Read metadata, specifically the file position upon entry.
using FilePosition = uint64_t;
static std::unordered_map<ReadKey, FilePosition> read_positions;

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

// Returns true if the filename matches the target filename. Currently attempts
// to find the last instance of the target filename. If the filename is found,
// it must be at the end of the filename string. This should be platform
// agnostic in that both paths in Unix-like and Windows should work.
bool is_match(const std::string &filename)
{
    size_t pos = filename.rfind(target_filename);
    return pos != std::string::npos &&
           filename.substr(pos).size() == target_filename.size();
}

// A normalized read_enter function. Called by both Linux and Windows
// specific calls.
void read_enter(const std::string &filename, uint64_t file_id,
                uint64_t position)
{
    // Check if the filename matched, if not we don't have to do anything.
    if (!is_match(filename)) {
        verbose_printf("file_taint read_enter: filename \"%s\" not matched\n",
                       filename.c_str());
        return;
    }

    // If taint isn't already enabled, turn it on. We've seen the file we want
    // to taint.
    if (!taint2_enabled()) {
        printf("file_taint read_enter: first time match of file \"%s\", "
               "enabling taint\n",
               target_filename.c_str());
        taint2_enable_taint();
    }

    // Construct the read key and record the associated start position of the
    // read.
    ReadKey key;
    OsiProc *proc = get_current_process(first_cpu);
    OsiThread *thr = get_current_thread(first_cpu);
    key.process_id = proc ? proc->pid : 0;
    key.thread_id = thr->tid;
    key.file_id = file_id;
    read_positions[key] = position;

    verbose_printf("file_taint read_enter matched: filename=\"%s\" pid=%lu "
                   "tid=%lu fid=%lu\n",
                   filename.c_str(), proc ? proc->pid : 0, thr->tid, file_id);

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
    ReadKey key;
    OsiProc *proc = get_current_process(first_cpu);
    OsiThread *thr = get_current_thread(first_cpu);
    key.process_id = proc ? proc->pid : 0;
    key.thread_id = thr->tid;
    key.file_id = file_id;

    // If we haven't seen a read with this key, don't do anything.
    if (read_positions.find(key) == read_positions.end()) {
        verbose_printf("file_taint read_return: don't know about read, "
                       "discarding (pid=%lu tid=%lu fid=%lu)\n",
                       proc ? proc->pid : 0, thr->tid, file_id);
        return;
    }

    verbose_printf("file_taint read_return: read return detected "
                   "(pid=%lu tid=%lu fid=%lu)\n",
                   proc ? proc->pid : 0, thr->tid, file_id);

    // We've seen the read, lookup the position of the file at the time of the
    // read enter.
    uint64_t read_start_pos = read_positions[key];

    // Figure out if the read overlapped our desired range.
    uint64_t range_start = std::max(read_start_pos, min_byte_pos);
    uint64_t range_end =
        std::min(read_start_pos + bytes_read - 1, max_byte_pos);

    bool print_apply_message = true;
    for (uint64_t i = 0; i < bytes_read && tainted_byte_count < max_byte_count;
         i++) {
        uint64_t file_pos = read_start_pos + i;
        if (range_start <= file_pos && file_pos <= range_end) {
            if (print_apply_message) {
                printf("*** applying %s taint labels %" PRIu64 "..%" PRIu64
                       " to buffer @ %" PRIu64 " ***\n",
                       positional ? "positional" : "uniform", range_start,
                       range_end, rr_get_guest_instr_count());
                print_apply_message = false;
            }
            hwaddr shadow_addr = panda_virt_to_phys(first_cpu, buffer_addr + i);
            verbose_printf(
                "file_taint applying label: file_pos=%lu buffer_addr=%lu\n",
                file_pos, buffer_addr + i);
            if (positional) {
                taint2_label_ram(shadow_addr, file_pos);
            } else {
                taint2_label_ram(shadow_addr, static_label);
            }
            tainted_byte_count++;
        }
    }

    // We've handled the read for this pid, tid, and file id. We have to see
    // another read enter before we can taint again for the same pid, tid and
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
    verbose_printf("file_taint windows object path: %s\n", ob_path.c_str());
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
            "file_taint read return: detected async read return, ignoring\n");
    } else if (io_status_block.status == STATUS_SUCCESS) {
        read_return(FileHandle, io_status_block.information, Buffer);
    } else {
        printf("file_taint windows_read_return: detected read failure, "
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
        "WARNING: file_taint only supports 32-bit x86 Linux and Windows.\n");
    return;
#endif
    if (actually_read != -1) {
        read_return(fd, actually_read, buffer);
    } else {
        printf("file_taint linux_read_return: detected read failure, "
               "ignoring.\n");
    }
}

void linux_pread_return(CPUState *cpu, target_ulong pc, uint32_t fd,
                        uint32_t buf, uint32_t count, uint64_t pos)
{
    // Just call the regular linux read return
    linux_read_return(cpu, pc, fd, buf, count);
}

    bool init_plugin(void *self)
{
    // Parse arguments for file_taint
    panda_arg_list *args = panda_get_args("file_taint");
    target_filename =
        panda_parse_string_req(args, "filename", "name of file to taint");
    min_byte_pos = panda_parse_uint64_opt(
        args, "start", 0,
        "minimum byte offset within the file to start tainting");
    max_byte_pos = panda_parse_uint64_opt(
        args, "end", UINT64_MAX, "last byte offset within the file to taint");
    max_byte_count = panda_parse_uint64_opt(args, "max_num_labels", 1000000,
                                            "maximum number of bytes to taint");
    positional = panda_parse_bool_opt(args, "pos",
                                      "enable or disable positional labels");
    static_label = panda_parse_uint32_opt(
        args, "label", 0xF11E, "the label to use (for non-positional labels)");
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
    panda_require("taint2");
    assert(init_taint2_api());

    // OS specific setup
    switch (panda_os_familyno) {
    case OS_WINDOWS: {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
        verbose_printf("file_taint: setting up Windows file read detection\n");
        PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
        PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);

        panda_require("wintrospection");
        assert(init_wintrospection_api());
#else
        fprintf(stderr, "ERROR: Windows is only supported on x86 (32-bit)\n");
        return false;
#endif
    } break;
    case OS_LINUX: {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
        verbose_printf("file_taint: setting up Linux file read detection\n");
        PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
        PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
        PPP_REG_CB("syscalls2", on_sys_pread64_enter, linux_pread_enter);
        PPP_REG_CB("syscalls2", on_sys_pread64_return, linux_pread_return);

        panda_require("osi_linux");
        assert(init_osi_linux_api());
#else
        fprintf(stderr, "ERROR: Linux is only supported on x86 (32-bit)\n");
        return false;
#endif
    } break;
    default: {
        fprintf(stderr, "file_taint2: OS not supported!\n");
        return false;
    } break;
    }

    return true;
}

void uninit_plugin(void *self) { }

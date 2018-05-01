#define __STDC_FORMAT_MACROS

#include <vector>
#include <map>
#include <string>
#include <cassert>

#include "taint2/taint2.h"

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

extern "C" {

#include "panda/rr/rr_log.h"
#include "panda/plog.h"
#include "panda/addr.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

// this provides the fd resolution magic

#include "osi_linux/osi_linux_ext.h"

#include "wintrospection/wintrospection.h"
#include "wintrospection/wintrospection_ext.h"

#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "taint2/taint2_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int get_loglevel() ;
void set_loglevel(int new_loglevel);

int cache_process_details(CPUState *cpu, TranslationBlock *tb);

#ifdef TARGET_I386
// Enable this option to record and cache process details at the start of each basic block.  By default, process
// details are recorded and cached when a read system call is encountered.
static bool cache_process_details_on_basic_block;
#endif

// Enable this option to do sanity checks when recording process details.  In particular, there should be a one
// to one correspondence between ASIDs and processes normally.  Enabling this validates that assertion holds.
static bool process_details_cache_sanity_check;

// Enable this option to not assume a one to one mapping between asids and processes.  Enabling this option
// always overwrites the running procs cache with the process details of the current process.
static bool always_overwrite_process_details_cache;

#include "file_taint_int_fns.h"
#include "file_taint.h"
PPP_PROT_REG_CB(on_file_byte_read)
PPP_CB_BOILERPLATE(on_file_byte_read)
}

static bool debug = false;

const char *taint_filename = 0;
bool positional_labels;
bool no_taint;
bool enable_taint_on_open;

#define MAX_FILENAME 256
bool saw_open = false;
bool read_callback = false;
uint32_t the_asid = 0;
uint32_t the_fd;

uint32_t end_label = 1000000;
uint32_t start_label = 0;

uint64_t first_instr = 0;

const char *taint_stdin = nullptr;

std::map< std::pair<uint32_t, uint32_t>, char *> asidfd_to_filename;

std::map <target_ulong, OsiProc> running_procs;

void file_taint_enable_read_callback(void) {
    read_callback = true;
}

// label this virtual address.  might fail, so
// returns true iff byte was labeled
bool label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t label_num) {
    hwaddr pa = panda_virt_to_phys(cpu, virt_addr);
    if (pa == (hwaddr) -1) {
        printf ("label_byte: virtual addr " TARGET_FMT_lx " not available\n", virt_addr);
        return false;
    }
    if (no_taint) {
        // don't print a message -- you'd have too many in this case
        return false;
    }
    if (positional_labels) {
        taint2_label_ram(pa, label_num);
    }
    else {
        taint2_label_ram(pa, 1);
    }
    if (pandalog) {
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.has_taint_label_virtual_addr = 1;
        ple.has_taint_label_physical_addr = 1;
        ple.has_taint_label_number = 1;
        ple.taint_label_virtual_addr = virt_addr;
        ple.taint_label_physical_addr = pa;
        if (positional_labels) {
            ple.taint_label_number = label_num;
        }
        else {
            ple.taint_label_number = 1;
        }
        pandalog_write_entry(&ple);
    }
    return true;
}



char *last_open_filename;
uint32_t last_open_asid;

#ifdef TARGET_I386

uint32_t guest_strncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(cpu, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        panda_virtual_memory_rw(cpu, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

void open_enter(CPUState *cpu, target_ulong pc, std::string filename, int32_t flags, int32_t mode) {
    if (!filename.empty()) {
        if (debug) printf ("open_enter: saw open of [%s]\n", filename.c_str());
    }
    if (filename.find(taint_filename) != std::string::npos) {
        saw_open = true;
        printf ("saw open of file we want to taint: [%s] insn %" PRId64 "\n", taint_filename, rr_get_guest_instr_count());
        the_asid = panda_current_asid(cpu);
        if (enable_taint_on_open && !no_taint && !taint2_enabled()) {
            uint64_t ins = rr_get_guest_instr_count();
            taint2_enable_taint();
            if (debug) printf ("file_taint: enabled taint2 @ ins  %" PRId64 "\n", ins);
        }
    }
}


void open_return(CPUState *cpu, uint32_t fd) {
    //    printf ("returning from open\n");
    if (saw_open && the_asid == panda_current_asid(cpu)) {
        saw_open = false;
        // get return value, which is the file descriptor for this file
        the_fd = fd;
        //        printf ("saw return from open of [%s]: asid=0x%x  fd=%d\n", taint_filename, the_asid, the_fd);
    }

}

// Assume 32-bit windows for this struct.
// WARNING: THIS MAY NOT WORK ON 64-bit!
typedef struct _OBJECT_ATTRIBUTES {
    uint32_t Length;
    uint32_t RootDirectory;
    uint32_t ObjectName;
    // There's more stuff here but we're ignoring it.
} OBJECT_ATTRIBUTES;

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

std::map<uint32_t, std::map<target_ulong, std::string>> windows_filenames;

std::string the_windows_filename;

// 179 NTSTATUS NtOpenFile (PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
// typedef void (*on_NtOpenFile_enter_t)(CPUState *cpu,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t ShareAccess,uint32_t OpenOptions);
void windows_open_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {
    char the_filename[MAX_FILENAME];
    OBJECT_ATTRIBUTES obj_attrs;
    UNICODE_STRING unicode_string;
    panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0);
    panda_virtual_memory_rw(cpu, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0);
    guest_wstrncpy(cpu, the_filename, MAX_FILENAME, unicode_string.Buffer);
    char *trunc_filename = the_filename;
    if (strncmp("\\??\\", the_filename, 4) == 0) {
        trunc_filename += 4;
    }
    the_windows_filename = std::string(trunc_filename);
    open_enter(cpu, pc, trunc_filename, 0, DesiredAccess);
}

// typedef void (*on_NtOpenFile_return_t)(CPUState *cpu,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t ShareAccess,uint32_t OpenOptions);
void windows_open_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {
    uint32_t Handle;
    panda_virtual_memory_rw(cpu, FileHandle, (uint8_t *)&Handle, 4, 0);
    if (debug) printf ("asid=0x%x filehandle=%d filename=[%s]\n", (uint)panda_current_asid(cpu), FileHandle, the_windows_filename.c_str());
    windows_filenames[panda_current_asid(cpu)][FileHandle] = the_windows_filename;
    open_return(cpu, Handle);
}

// Going into a read might cause the scheduler to run, which could leave
// multiple reads outstanding at once. But should be at most one per thread. So
// we can track per-thread. Asid plus SP should correspond to a guest thread.

struct ThreadInfo {
    target_ulong asid;
    target_ulong sp;

    bool operator<(const ThreadInfo &other) const {
        return std::tie(asid, sp) < std::tie(other.asid, other.sp);
    }
};

struct ReadInfo {
    std::string filename;
    uint64_t pos;
    target_ulong buf;
    uint32_t count;
};

// Track reads, but only the ones we care about.
std::map<ThreadInfo, ReadInfo> seen_reads;

uint64_t last_pos = (uint64_t) -1;

void read_enter(CPUState *cpu, target_ulong pc, std::string filename, uint64_t pos, uint32_t buf, uint32_t count) {
    // these things are only known at enter of read call
    last_pos = pos;
    if (debug) printf ("read_enter filename=[%s]\n", filename.c_str());
    std::string read_filename = taint_stdin ? "stdin" : taint_filename;

    if(!cache_process_details_on_basic_block) cache_process_details(cpu, NULL);
    auto it = running_procs.find(the_asid);
    if (taint_stdin) {
        if (it == running_procs.end()) {
            if (debug) printf("read_enter unknown proc.\n");
            return;
        }
        std::string proc_name = it->second.name;
        if (proc_name.find(taint_stdin) == std::string::npos) {
            if (debug) printf("read_enter wrong proc %s.\n", proc_name.c_str());
            return;
        }
    }

    if (filename.find(read_filename) != std::string::npos) {
        target_ulong sp;
        if (panda_os_familyno == OS_WINDOWS) {
            sp = panda_current_sp(cpu) + 4;
        }
        else {
            sp = panda_current_sp(cpu);
        }
        if (debug) printf ("read_enter: asid=0x" TARGET_FMT_lx " sp=0x" TARGET_FMT_lx "\n", panda_current_asid(cpu), sp);
        ThreadInfo thread{ panda_current_asid(cpu), sp };

        seen_reads[thread] = ReadInfo{ filename, pos, buf, count };
    }
}

// 3 long sys_read(unsigned int fd, char __user *buf, size_t count);
// typedef void (*on_sys_read_return_t)(CPUState *cpu,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count);
void read_return(CPUState *cpu, target_ulong pc, uint32_t buf, uint32_t actual_count) {
    ThreadInfo thread{ panda_current_asid(cpu), panda_current_sp(cpu) - get_ntreadfile_esp_off() };
    auto it = seen_reads.find(thread);
    if (it != seen_reads.end()) {
        ReadInfo read_info = it->second;
        // These are the start and end of the current range of labels.
        uint32_t read_start = read_info.pos;
        uint32_t read_end = read_start + actual_count;
        if (debug) printf ("returning from read of [%s] count=%u\n", taint_filename, actual_count);
        // check if we overlap the range we want to label.
        if (read_start < end_label && read_end > start_label) {
            uint32_t range_start = std::max(read_start, start_label);
            uint32_t range_end = std::min(read_end, end_label);
            printf("*** applying %s taint labels %u..%u to buffer @ %lu\n",
                    positional_labels ? "positional" : "uniform",
                    range_start, range_end - 1, rr_get_guest_instr_count());
            uint32_t num_labeled = 0;
            uint32_t i = 0;
            for (uint32_t l = range_start; l < range_end; l++) {
                // pass address and byte number to a callback instead of
                // tainting
                if (read_callback) {
                    PPP_RUN_CB(on_file_byte_read, cpu, read_info.buf + i, l)
                } else {
                    if (label_byte(cpu, read_info.buf + i,
                                positional_labels ? l : 1))
                        num_labeled++;
                }
                i++;
            }
            printf("%u bytes labeled for this read\n", range_end - range_start);
        }
        last_pos += actual_count;
        seen_reads.erase(it);
    }
}

// 273 NTSTATUS NtReadFile (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE UserApcRoutine, PVOID UserApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG BufferLength, PLARGE_INTEGER ByteOffset, PULONG Key);
// typedef void (*on_NtReadFile_enter_t)(CPUState *cpu,target_ulong pc,uint32_t FileHandle,uint32_t Event,uint32_t UserApcRoutine,uint32_t UserApcContext,uint32_t IoStatusBlock,uint32_t Buffer,uint32_t BufferLength,uint32_t ByteOffset,uint32_t Key);

void windows_read_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {
    int64_t offset = -1;
    if (ByteOffset != 0) {
        // Byte offset into file is specified (pointer to LARGE_INTEGER). Read and interpret.
        panda_virtual_memory_rw(cpu, ByteOffset, (uint8_t *)&offset, sizeof(offset), 0);
        //printf("NtReadFile: %lu[%ld]\n", (unsigned long)FileHandle, offset);
    } else {
        //printf("NtReadFile: %lu[]\n", (unsigned long)FileHandle);
    }

    char *filename = get_handle_name(cpu, get_current_proc(cpu), FileHandle);
    if (ByteOffset && (offset >= 0 && offset < (1L << 48))) {
        read_enter(cpu, pc, filename, offset, Buffer, BufferLength);
    }
    else {
        offset = get_file_handle_pos(cpu, get_current_proc(cpu), FileHandle);
        if (offset != -1)
            read_enter(cpu, pc, filename, offset, Buffer, BufferLength);
        else // last resort. just assume last_pos.
            read_enter(cpu, pc, filename, last_pos, Buffer, BufferLength);
    }
    g_free(filename);
}

#define STATUS_SUCCESS 0
typedef struct _IO_STATUS_BLOCK {
    uint32_t Nothing;
    uint32_t Information;
} IO_STATUS_BLOCK;

void windows_read_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    if (env->regs[R_EAX] != STATUS_SUCCESS) return;
    IO_STATUS_BLOCK io_status_block;
    uint32_t actual_count = BufferLength;
    if (panda_virtual_memory_rw(cpu, IoStatusBlock, (uint8_t *)&io_status_block, sizeof(io_status_block), 0) != -1) {
        actual_count = io_status_block.Information;
    } else {
        if (debug) printf("file_taint: failed to read IoStatusBlock @ %x\n", IoStatusBlock);
    }
    read_return(cpu, pc, Buffer, actual_count);
}

// 66 NTSTATUS NtCreateFile (PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
// typedef void (*on_NtCreateFile_enter_t)(CPUState *cpu,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t AllocationSize,uint32_t FileAttributes,uint32_t ShareAccess,uint32_t CreateDisposition,uint32_t CreateOptions,uint32_t EaBuffer,uint32_t EaLength);
void windows_create_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {
    windows_open_enter(cpu, pc, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateOptions);
}

// typedef void (*on_NtCreateFile_return_t)(CPUState *cpu,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t AllocationSize,uint32_t FileAttributes,uint32_t ShareAccess,uint32_t CreateDisposition,uint32_t CreateOptions,uint32_t EaBuffer,uint32_t EaLength);
void windows_create_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {
    windows_open_return(cpu, pc, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateOptions);
}


char stdin_filename[] = "stdin";

void linux_pread_enter(CPUState *cpu, target_ulong pc,
        uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos) {
    target_ulong asid = panda_current_asid(cpu);
    if(!cache_process_details_on_basic_block) cache_process_details(cpu, NULL);
    if (running_procs.count(asid) == 0) {
        if (debug) printf ("linux_read_enter for asid=0x%x fd=%d -- dont know about that asid.  discarding \n", (unsigned int) asid, (int) fd);
        return;
    }
    char *filename;
    if (taint_stdin) {
        filename = stdin_filename;
        pos = 0;
    }
    else {
        OsiProc& proc = running_procs[asid];
        filename = osi_linux_fd_to_filename(cpu, &proc, fd);
        if (pos == (uint64_t)-1) {
            pos = osi_linux_fd_to_pos(cpu, &proc, fd);
        }
        if (filename==NULL) {
            if (debug)
                printf ("linux_read_enter for asid=0x%x pid=%d cmd=[%s] fd=%d -- that asid is known but resolving fd failed.  discarding\n",
                        (unsigned int) asid, (int) proc.pid, proc.name, (int) fd);
            return;
        }
        if (debug) printf ("linux_read_enter for asid==0x%x fd=%d filename=[%s] count=%d pos=%u\n", (unsigned int) asid, (int) fd, filename, count, (unsigned int) pos);
    }
    read_enter(cpu, pc, filename, pos, buf, count);
}

void linux_pread_return(CPUState *cpu, target_ulong pc,
        uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos) {
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    read_return(cpu, pc, buf, env->regs[R_EAX]);
}

void linux_read_return(CPUState *cpu, target_ulong pc,
        uint32_t fd, uint32_t buf, uint32_t count) {
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    read_return(cpu, pc, buf, env->regs[R_EAX]);
}

void linux_read_enter(CPUState *cpu, target_ulong pc,
        uint32_t fd, uint32_t buf, uint32_t count) {
    linux_pread_enter(cpu, pc, fd, buf, count, -1);
}

#endif

int file_taint_enable(CPUState *cpu, target_ulong pc) {
    if (!no_taint && !taint2_enabled()) {
        uint64_t ins = rr_get_guest_instr_count();
        if (ins > first_instr) {
            taint2_enable_taint();
            if (debug) printf (" enabled taint2 @ ins  %" PRId64 "\n", ins);
        }
    }
    return 0;
}


#ifdef TARGET_I386
void linux_open_enter(CPUState *cpu, target_ulong pc, uint32_t filename, int32_t flags, int32_t mode) {
    char the_filename[MAX_FILENAME];
    guest_strncpy(cpu, the_filename, MAX_FILENAME, filename);
    if (debug) printf ("linux open asid=0x%x filename=[%s]\n", (unsigned int) panda_current_asid(cpu), the_filename);
    open_enter(cpu, pc, the_filename, flags, mode);
}
#endif /* TARGET_I386 */



int cache_process_details(CPUState *cpu, TranslationBlock *tb__unused) {
    if (panda_in_kernel(cpu)) {
        OsiProc *p = get_current_process(cpu);
        //some sanity checks on what we think the current process is
        // we couldn't find the current task
        if (p == NULL) return 0;
        // this means we didnt find current task
        if (p->offset == 0) {
            free_osiproc(p);
            return 0;
        }
        // or the name
        if (p->name == 0) {
            free_osiproc(p);
            return 0;
        }
        // weird -- this is just not ok
        if (((int) p->pid) == -1) {
            free_osiproc(p);
            return 0;
        }
        uint32_t n = strnlen(p->name, 32);
        // yuck -- name is one char
        if (n<2) {
            free_osiproc(p);
            return 0;
        }
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // yuck -- name doesnt consist of solely printable characters
        if (np != n) {
            free_osiproc(p);
            return 0;
        }
        target_ulong asid = panda_current_asid(cpu);
        if (always_overwrite_process_details_cache || (running_procs.count(asid) == 0)) {
            if (debug) printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->offset);
            running_procs[asid] = *p;
            free(p); // cannot free members of p here, they are still in use
        } else {
            if(process_details_cache_sanity_check) {
                // Check that the current process details match the process details previously cached.
                OsiProc p2 = running_procs[asid];
                assert(p->offset == p2.offset);
                assert(p->asid == p2.asid);
                assert(p->pid == p2.pid);
                assert(p->ppid == p2.ppid);
            }
            free_osiproc(p);
        }
    }
    return 0;
}


bool init_plugin(void *self) {

#ifdef TARGET_I386
    panda_cb pcb;
    panda_arg_list *args;
    args = panda_get_args("file_taint");
    taint_filename = panda_parse_string_opt(args, "filename", "abc123", "filename to taint");
    positional_labels = panda_parse_bool_opt(args, "pos", "use positional labels");
    read_callback = panda_parse_bool_opt(args, "read_callback", "Do not label file bytes as tainted but rather pass address and offset to a callback");
    no_taint = panda_parse_bool_opt(args, "notaint", "don't actually taint anything");
    end_label = panda_parse_ulong_opt(args, "max_num_labels", 1000000, "maximum label number to use");
    end_label = panda_parse_ulong_opt(args, "end", end_label, "which byte to end tainting at");
    start_label = panda_parse_ulong_opt(args, "start", 0, "which byte to start tainting at");
    enable_taint_on_open = panda_parse_bool_opt(args, "enable_taint_on_open", "don't turn on taint until the file is opened");
    first_instr = panda_parse_uint64_opt(args, "first_instr", 0, "don't turn on taint until this instruction");
    taint_stdin = panda_parse_string_opt(args, "use_stdin_for", nullptr, "not quite finished don't use");
    cache_process_details_on_basic_block = panda_parse_bool_opt(args, "cache_process_details_on_basic_block", "record asid at the start of each basic block (previous default behavior)");
    always_overwrite_process_details_cache = panda_parse_bool_opt(args, "always_overwrite_process_details_cache", "never cache process details, always use current process details (previous default behavior)");
    if(!always_overwrite_process_details_cache) {
        process_details_cache_sanity_check = panda_parse_bool_opt(args, "process_details_cache_sanity_check", "validate one to one match between asid and process during playback");
    } else {
        process_details_cache_sanity_check = false;
    }
    debug = panda_parse_bool_opt(args, "debug", "debug mode");

    printf ("taint_filename = [%s]\n", taint_filename);
    printf ("positional_labels = %d\n", positional_labels);
    printf ("no_taint = %d\n", no_taint);
    printf ("end_label = %d\n", end_label);
    printf ("first_instr = %" PRId64 " \n", first_instr);
    printf ("cache_process_details_on_basic_block = %d\n", cache_process_details_on_basic_block);
    printf ("process_details_cache_sanity_check = %d\n", process_details_cache_sanity_check);
    printf ("always_overwrite_process_details_cache = %d\n", always_overwrite_process_details_cache);
    printf ("debug = %d\n", debug);

    // you must use '-os os_name' cmdline arg!
    assert (!(panda_os_familyno == OS_UNKNOWN));

    panda_require("osi");
    assert(init_osi_api());
    panda_require("syscalls2");

    if (taint_stdin) {
        printf("tainting stdin\n");
        assert (panda_os_familyno == OS_LINUX);
    }

    if (panda_os_familyno == OS_LINUX) {
        panda_require("osi_linux");
        assert(init_osi_linux_api());

        PPP_REG_CB("syscalls2", on_sys_open_enter, linux_open_enter);
        PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
        PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
        PPP_REG_CB("syscalls2", on_sys_pread64_enter, linux_pread_enter);
        PPP_REG_CB("syscalls2", on_sys_pread64_return, linux_pread_return);
    }

    if (panda_os_familyno == OS_WINDOWS) {
        panda_require("wintrospection");
        assert(init_wintrospection_api());

        PPP_REG_CB("syscalls2", on_NtOpenFile_enter, windows_open_enter);
        PPP_REG_CB("syscalls2", on_NtOpenFile_return, windows_open_return);
        PPP_REG_CB("syscalls2", on_NtCreateFile_enter, windows_create_enter);
        PPP_REG_CB("syscalls2", on_NtCreateFile_return, windows_create_return);
        PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
        PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);
    }

    // this sets up the taint api fn ptrs so we have access
    if (!no_taint) {
        if (debug) printf("file_taint: initializing taint2 plugin\n");
        panda_require("taint2");
        assert(init_taint2_api());
        if (!enable_taint_on_open && first_instr == 0) {
            if (debug) printf("file_taint: turning on taint at replay beginning\n");
            taint2_enable_taint();
        }
    }

    if (!no_taint && first_instr > 0) {
        if (debug) printf ("file_taint: turning on taint at instruction %" PRId64 "\n", first_instr);
        // only need this callback if we are turning on taint late
        pcb.before_block_translate = file_taint_enable;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    }

    if(cache_process_details_on_basic_block) {
        pcb.before_block_exec = cache_process_details;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }

#else
    printf ("file_taint: only works for x86 target (really just 32-bit)\n");
    return false;

#endif
    return true;
}



void uninit_plugin(void *self) {
}


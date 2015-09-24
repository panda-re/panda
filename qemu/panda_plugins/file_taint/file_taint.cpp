#define __STDC_FORMAT_MACROS

#include "panda/panda_addr.h"

#include "../taint2/taint2.h"

extern "C" {

    
#include "rr_log.h"    
#include "qemu-common.h"
#include "cpu.h"
#include "panda_plugin.h"
#include "pandalog.h"
#include "panda_common.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

    // this provides the fd resolution magic
#include "../osi_linux/osi_linux_ext.h"
    
#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../taint2/taint2_ext.h"
#include "panda_plugin_plugin.h" 
    
    bool init_plugin(void *);
    void uninit_plugin(void *);
    
    int get_loglevel() ;
    void set_loglevel(int new_loglevel);

}

#include <vector>
#include <map>
#include <string>
 
const char *taint_filename = 0;
bool positional_labels = true;
bool no_taint = true;

#define MAX_FILENAME 256
bool saw_open = false;
uint32_t the_asid = 0;
uint32_t the_fd;

uint32_t end_label = 1000000;
uint32_t start_label = 0;

uint64_t first_instr = 0;

std::map< std::pair<uint32_t, uint32_t>, char *> asidfd_to_filename;

std::map <target_ulong, OsiProc> running_procs;


// label this virtual address.  might fail, so
// returns true iff byte was labeled
bool label_byte(CPUState *env, target_ulong virt_addr, uint32_t label_num) {
    target_phys_addr_t pa = panda_virt_to_phys(env, virt_addr);
    if (pa == (target_phys_addr_t) -1) {
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
// This is our proxy for file position. Approximate because of fseek etc.
uint64_t file_pos = 0;

uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        uint8_t c;
        panda_virtual_memory_rw(env, guest_addr+i, &c, 1, 0);
        buf[i] = c;
        if (c==0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        panda_virtual_memory_rw(env, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

void open_enter(CPUState *env, target_ulong pc, std::string filename, int32_t flags, int32_t mode) {
    if (!filename.empty()) {
        printf ("open_enter: saw open of [%s]\n", filename.c_str());
    }
    if (filename.find(taint_filename) != std::string::npos) {
        saw_open = true;
        printf ("saw open of file we want to taint: [%s] insn %" PRId64 "\n", taint_filename, rr_get_guest_instr_count());
        the_asid = panda_current_asid(env);
    }
}


void open_return(CPUState* env, uint32_t fd) {
    //    printf ("returning from open\n");
    if (saw_open && the_asid == panda_current_asid(env)) {
        saw_open = false;
        // get return value, which is the file descriptor for this file
        the_fd = fd;
        //        printf ("saw return from open of [%s]: asid=0x%x  fd=%d\n", taint_filename, the_asid, the_fd);
    }
            
}

void seek_enter(CPUState *env, uint32_t fd, uint64_t abs_offset) {
    if (the_fd == fd && the_asid == panda_current_asid(env)) {
        file_pos = abs_offset;
    }
}

void windows_seek_enter(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t IoStatusBlock,uint32_t FileInformation,uint32_t Length,uint32_t FileInformationClass) {
    uint64_t Position = 0;
    if (FileInformationClass == 14) { // FilePositionInformation
        panda_virtual_memory_rw(env, FileInformation, (uint8_t *) &Position, sizeof(Position), false);
        printf("DEBUG: NtSetInformationFile(fd = %u, offset = %" PRIu64 ")\n", FileHandle, Position);
        seek_enter(env, FileHandle, Position);
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
// typedef void (*on_NtOpenFile_enter_t)(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t ShareAccess,uint32_t OpenOptions);
void windows_open_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {
    char the_filename[MAX_FILENAME];
    OBJECT_ATTRIBUTES obj_attrs;
    UNICODE_STRING unicode_string;

    panda_virtual_memory_rw(env, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0);
    panda_virtual_memory_rw(env, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0);
    guest_wstrncpy(env, the_filename, MAX_FILENAME, unicode_string.Buffer);

    char *trunc_filename = the_filename;
    if (strncmp("\\??\\", the_filename, 4) == 0) {
        trunc_filename += 4;
    }

    the_windows_filename = std::string(trunc_filename);
    
    open_enter(env, pc, trunc_filename, 0, DesiredAccess);
}

// typedef void (*on_NtOpenFile_return_t)(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t ShareAccess,uint32_t OpenOptions);
void windows_open_return(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {
    uint32_t Handle;
    panda_virtual_memory_rw(env, FileHandle, (uint8_t *)&Handle, 4, 0);
    windows_filenames[panda_current_asid(env)][FileHandle] = the_windows_filename;
    open_return(env, Handle);
}

uint32_t the_buf;
uint32_t the_count;
bool saw_read = false;

uint32_t last_read_buf;
uint64_t last_pos = (uint64_t) -1;

void read_enter(CPUState* env, target_ulong pc, std::string filename, uint64_t pos, target_ulong buf, uint32_t count) { 
    // these things are only known at enter of read call
    the_asid = panda_current_asid(env);
    last_read_buf = buf;
    last_pos = pos;    
    saw_read = false;
    if (0 == strcmp(filename.c_str(), taint_filename)) {
        printf ("read_enter: asid=0x%x saw read of %d bytes in file we want to taint\n", the_asid, count);
        saw_read = true;
    }
}

// 3 long sys_read(unsigned int fd, char __user *buf, size_t count);
// typedef void (*on_sys_read_return_t)(CPUState* env,target_ulong pc,uint32_t fd,target_ulong buf,uint32_t count);
void read_return(CPUState* env, target_ulong pc, target_ulong buf, uint32_t actual_count) {

    if (saw_read && panda_current_asid(env) == the_asid) {
        // These are the start and end of the current range of labels.
        uint32_t read_start = last_pos;
        uint32_t read_end = last_pos + actual_count;        
        printf ("returning from read of [%s] count=%u\n", taint_filename, actual_count);
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
                if (label_byte(env, last_read_buf + i,
                               positional_labels ? l : 0))
                    num_labeled ++;
                i ++;
            }
            printf("%u bytes labeled for this read\n", range_end - range_start);
        }
        last_pos += actual_count;
        //        printf (" ... done applying labels\n");
        saw_read = false;
    }
}

// 273 NTSTATUS NtReadFile (HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE UserApcRoutine, PVOID UserApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG BufferLength, PLARGE_INTEGER ByteOffset, PULONG Key);
// typedef void (*on_NtReadFile_enter_t)(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t Event,uint32_t UserApcRoutine,uint32_t UserApcContext,uint32_t IoStatusBlock,uint32_t Buffer,uint32_t BufferLength,uint32_t ByteOffset,uint32_t Key);

void windows_read_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {
    int64_t offset;
    if (ByteOffset != 0) {
        // Byte offset into file is specified (pointer to LARGE_INTEGER). Read and interpret.
        panda_virtual_memory_rw(env, ByteOffset, (uint8_t *)&offset, sizeof(offset), 0);
        //printf("NtReadFile: %lu[%ld]\n", (unsigned long)FileHandle, offset);
        if (offset >= 0 && offset < (1L << 48)) { // otherwise invalid.
            file_pos = offset;
        }
    } else {
        //printf("NtReadFile: %lu[]\n", (unsigned long)FileHandle);
    }

    std::string filename = windows_filenames[panda_current_asid(env)][FileHandle];
    
    read_enter(env, pc, filename, 0, Buffer, BufferLength);
}

#define STATUS_SUCCESS 0
typedef struct _IO_STATUS_BLOCK {
    uint32_t Nothing;
    uint32_t Information;
} IO_STATUS_BLOCK;

void windows_read_return(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {
    if (EAX != STATUS_SUCCESS) return;
    IO_STATUS_BLOCK io_status_block;
    uint32_t actual_count = BufferLength;
    if (panda_virtual_memory_rw(env, IoStatusBlock, (uint8_t *)&io_status_block, sizeof(io_status_block), 0) != -1) {
        actual_count = io_status_block.Information;
    } else {
        printf("file_taint: failed to read IoStatusBlock @ %x\n", IoStatusBlock);
    }

    read_return(env, pc, Buffer, actual_count);
}

// 66 NTSTATUS NtCreateFile (PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
// typedef void (*on_NtCreateFile_enter_t)(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t AllocationSize,uint32_t FileAttributes,uint32_t ShareAccess,uint32_t CreateDisposition,uint32_t CreateOptions,uint32_t EaBuffer,uint32_t EaLength);
void windows_create_enter(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {
    windows_open_enter(env, pc, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateOptions);
}

// typedef void (*on_NtCreateFile_return_t)(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t DesiredAccess,uint32_t ObjectAttributes,uint32_t IoStatusBlock,uint32_t AllocationSize,uint32_t FileAttributes,uint32_t ShareAccess,uint32_t CreateDisposition,uint32_t CreateOptions,uint32_t EaBuffer,uint32_t EaLength);
void windows_create_return(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {
    windows_open_return(env, pc, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateOptions);
}

void linux_read_enter(CPUState *env, target_ulong pc, uint32_t fd, target_ulong buf, uint32_t count) {
    target_ulong asid = panda_current_asid(env);
    if (running_procs.count(asid) == 0) {
        printf ("linux_read_enter for asid=0x%x fd=%d -- dont know about that asid.  discarding \n", (unsigned int) asid, (int) fd);
        return;
    }
    OsiProc proc = running_procs[panda_current_asid(env)];        
    char *filename = osi_linux_fd_to_filename(env, &proc, fd);
    uint64_t pos = osi_linux_fd_to_pos(env, &proc, fd);
    if (filename==NULL) {
        printf ("linux_read_enter for asid=0x%x pid=%d cmd=[%s] fd=%d -- that asid is known but resolving fd failed.  discarding\n",
                (unsigned int) asid, (int) proc.pid, proc.name, (int) fd);
        return;
    }
    printf ("linux_read_enter for asid==0x%x fd=%d filename=[%s] count=%d pos=%u\n", (unsigned int) asid, (int) fd, filename, count, (unsigned int) pos);        
    read_enter(env, pc, filename, pos, buf, count);
}

void linux_read_return(CPUState *env, target_ulong pc, uint32_t fd, target_ulong buf, uint32_t count) {
    read_return(env, pc, buf, EAX);
}

#endif

extern uint64_t replay_get_guest_instr_count(void);
bool taint_is_enabled = false;

int file_taint_enable(CPUState *env, target_ulong pc) {
    if (!no_taint && !taint_is_enabled) {
        uint64_t ins = replay_get_guest_instr_count();
        //        printf ("ins= %" PRId64 "  first_ins = %" PRId64" %d\n",
        //                ins, first_instr, (ins > first_instr) );

        if (ins > first_instr) {
            
            taint_is_enabled = true;
            taint2_enable_taint();
            printf (" @ ins  %" PRId64 "\n", ins); 
        }
    }
    return 0;
}


#ifdef TARGET_I386
void linux_open_enter(CPUState *env, target_ulong pc, target_ulong filename, int32_t flags, int32_t mode) {
    char the_filename[MAX_FILENAME];
    guest_strncpy(env, the_filename, MAX_FILENAME, filename);    
    printf ("linux open asid=0x%x filename=[%s]\n", (unsigned int) panda_current_asid(env), the_filename);
    open_enter(env, pc, the_filename, flags, mode);
}
#endif /* TARGET_I386 */



// get current process before each bb execs
// which will probably help us actually know the current process
int osi_foo(CPUState *env, TranslationBlock *tb) {

    if (panda_in_kernel(env)) {

        OsiProc *p = get_current_process(env);      

        //some sanity checks on what we think the current process is
        // this means we didnt find current task
        if (p->offset == 0) return 0;
        // or the name
        if (p->name == 0) return 0;
        // this is just not ok
        if (((int) p->pid) == -1) return 0;
        uint32_t n = strnlen(p->name, 32);
        // name is one char?
        if (n<2) return 0;
        uint32_t np = 0;
        for (uint32_t i=0; i<n; i++) {
            np += (isprint(p->name[i]) != 0);
        }
        // name doesnt consist of solely printable characters
        //        printf ("np=%d n=%d\n", np, n);
        if (np != n) return 0;
        target_ulong asid = panda_current_asid(env);
        if (running_procs.count(asid) == 0) {
            printf ("adding asid=0x%x to running procs.  cmd=[%s]  task=0x%x\n", (unsigned int)  asid, p->name, (unsigned int) p->offset);
        }
        running_procs[asid] = *p;
    }
    
    return 0;
}


bool init_plugin(void *self) {

    printf("Initializing plugin file_taint\n");

    panda_arg_list *args;
    args = panda_get_args("file_taint");
    taint_filename = panda_parse_string(args, "filename", "abc123");
    positional_labels = panda_parse_bool(args, "pos");
    // used to just find the names of files that get 
    no_taint = panda_parse_bool(args, "notaint");
    end_label = panda_parse_ulong(args, "max_num_labels", 1000000);
    end_label = panda_parse_ulong(args, "end", end_label);
    start_label = panda_parse_ulong(args, "start", 0);
    first_instr = panda_parse_uint64(args, "first_instr", 0);

    printf ("taint_filename = [%s]\n", taint_filename);
    printf ("positional_labels = %d\n", positional_labels);
    printf ("no_taint = %d\n", no_taint);
    printf ("end_label = %d\n", end_label);
    printf ("first_instr = %" PRId64 " \n", first_instr);

    panda_require("osi_linux");
    assert(init_osi_linux_api());
    
    panda_require("osi");
    // this sets up OS introspection API
    assert(init_osi_api());
    
    panda_require("syscalls2");

    // this sets up the taint api fn ptrs so we have access
    if (!no_taint) {
        panda_require("taint2");
        assert(init_taint2_api());
        if (first_instr == 0) {
            taint2_enable_taint();
        }
    }
    
    panda_cb pcb;        

    if (first_instr > 0) {
        // only need this callback if we are turning on taint late
        pcb.before_block_translate = file_taint_enable;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
    }

#if defined(TARGET_I386)

    {
        panda_cb pcb;
        pcb.before_block_exec = osi_foo;
        panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    }

    PPP_REG_CB("syscalls2", on_sys_open_enter, linux_open_enter);
    
    
    PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
    PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);

    PPP_REG_CB("syscalls2", on_NtOpenFile_enter, windows_open_enter);
    PPP_REG_CB("syscalls2", on_NtOpenFile_return, windows_open_return);

    PPP_REG_CB("syscalls2", on_NtCreateFile_enter, windows_create_enter);
    PPP_REG_CB("syscalls2", on_NtCreateFile_return, windows_create_return);

    PPP_REG_CB("syscalls2", on_NtReadFile_enter, windows_read_enter);
    PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);

    PPP_REG_CB("syscalls2", on_NtSetInformationFile_enter, windows_seek_enter);


#endif
    return true;
}



void uninit_plugin(void *self) {
}


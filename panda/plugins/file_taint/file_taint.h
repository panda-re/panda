#ifndef __FILE_TAINT_H_
#define __FILE_TAINT_H_

typedef void (* on_file_byte_read_t)(CPUState *cpu, target_ulong virt_addr, uint32_t file_offset);


int get_loglevel();

void set_loglevel(int new_loglevel);

bool init_plugin(void *self);

void uninit_plugin(void *self);

int cache_process_details(CPUState *cpu, TranslationBlock *tb);

void file_taint_enable_read_callback(void);

bool label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t label_num);


#ifdef TARGET_I386


int file_taint_enable(CPUState *cpu, target_ulong pc);

void open_enter(CPUState *cpu, target_ulong pc, std::string filename, int32_t flags, int32_t mode);

void open_return(CPUState *cpu, uint32_t fd);

// Going into a read might cause the scheduler to run, which could leave
// multiple reads outstanding at once. But should be at most one per thread. So
// we can track per-thread. Asid plus SP should correspond to a guest thread.
struct ThreadInfo {
    target_ulong asid;  //address space identifier
    target_ulong sp;    // stack pointer

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

void read_enter(CPUState *cpu, target_ulong pc, std::string filename, uint64_t pos, uint32_t buf, uint32_t count);

void read_return(CPUState *cpu, target_ulong pc, uint32_t buf, uint32_t actual_count, uint32_t bytes_left_on_stack);

int cache_process_details(CPUState *cpu, TranslationBlock *tb__unused);

/* LINUX functions */

uint32_t guest_strncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr);

void linux_open_enter(CPUState *cpu, target_ulong pc, uint32_t filename, int32_t flags, int32_t mode);

void linux_openat_enter(CPUState *cpu, target_ulong pc, int32_t dirfd, uint32_t filename, int32_t flags, int32_t mode);

void linux_pread_enter(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);

void linux_pread_return(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos);

void linux_read_return(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);

void linux_read_enter(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count);

/* WINDOWS functions */

uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr);

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


void windows_open_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess,
  uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);

void windows_open_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess,
  uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions);

void windows_create_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess,
  uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes,
  uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength);

void windows_create_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess,
  uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes,
  uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength);


void windows_read_enter(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event,
  uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer,
  uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key);

typedef struct _IO_STATUS_BLOCK {
    uint32_t Nothing;
    uint32_t Information;
} IO_STATUS_BLOCK;

void windows_read_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event,
  uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer,
  uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key);

#endif /* end TARGET_I386 */

#endif /* end __FILE_TAINT_H_ */

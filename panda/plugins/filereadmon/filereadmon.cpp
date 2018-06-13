#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <functional>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <memory>
#include <vector>
#include <iostream>
#include <string>

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "syscalls2/syscalls_common.h"

#include "osi/osi_types.h"

#define MAX_FILENAME 256

extern "C" {

target_ulong current_asid = 0;

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

typedef struct _IO_STATUS_BLOCK {
    union {
        uint32_t Status;
        uint32_t Pointer;
    };
    uint32_t Information;
} IO_STATUS_BLOCK;
    

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

#if defined(TARGET_I386) && !defined(TARGET_X86_64)

// Print system call arguments and data read on successful return from NtReadFile system call

void my_NtReadFile_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {

    // Get the return value from EAX
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    uint32_t return_value = env->regs[R_EAX];

    if(return_value) {
    } else {
        fprintf(stderr, "%x: NtReadFile(FileHandle=%x, Event=%x, ApcRoutine=%x, ApcContext=%x, IoStatusBlock=%x, Buffer=%x, BufferLength=%x, ByteOffset=%x, Key=%x)\n",
            current_asid, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);

        IO_STATUS_BLOCK io_status_block;
        panda_virtual_memory_rw(cpu, IoStatusBlock, (uint8_t *)&io_status_block, sizeof(io_status_block), 0);
        fprintf(stderr, "Bytes Read=%x\n", io_status_block.Information);

        // Print bytes read
        unsigned char *s=(unsigned char *)malloc(io_status_block.Information);
        if(s) {
            panda_virtual_memory_rw(cpu, Buffer, (uint8_t *)s, io_status_block.Information, 0);
            for(int i=0; i<io_status_block.Information; i++) {
                fprintf(stderr, "%02x ", s[i]);
            }
            fprintf(stderr, "\n");
            free(s);
        }
    }
}



// Print return value, filename, and openoptions when NtOpenFile system call returns

void my_NtOpenFile_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {

    // Get the return value from EAX
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    uint32_t return_value = env->regs[R_EAX];

    // Get the file handle from the FileHandle pointer parameter
    uint32_t handle;
    panda_virtual_memory_rw(cpu, FileHandle, (uint8_t *)&handle, 4, 0);

    char the_filename_buffer[MAX_FILENAME];
    char *the_filename = the_filename_buffer;
    OBJECT_ATTRIBUTES obj_attrs;
    UNICODE_STRING unicode_string;
    panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0);
    panda_virtual_memory_rw(cpu, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0);
    guest_wstrncpy(cpu, the_filename, MAX_FILENAME, unicode_string.Buffer);
    //if(!strncmp(the_filename, "\\??\\", 4)) the_filename+=4;

    if(return_value) {
        fprintf(stderr, "Returning from NtOpenFile (error), return_value=%x, filename=%s, OpenOptions=%x\n", return_value, the_filename, OpenOptions);
    } else {
        fprintf(stderr, "%x: Returning from NtOpenFile (success), handle=%x, filename=%s, OpenOptions=%x\n",
            current_asid, handle, the_filename, OpenOptions);
    }
}

// Print return value, filename, and createoptions when NtCreateFile system call returns

void my_NtCreateFile_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {

    // Get the return value from EAX
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    uint32_t return_value = env->regs[R_EAX];

    // Get the file handle from the FileHandle pointer parameter
    uint32_t handle;
    panda_virtual_memory_rw(cpu, FileHandle, (uint8_t *)&handle, 4, 0);

    char the_filename_buffer[MAX_FILENAME];
    char *the_filename = the_filename_buffer;
    OBJECT_ATTRIBUTES obj_attrs;
    UNICODE_STRING unicode_string;
    panda_virtual_memory_rw(cpu, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0);
    panda_virtual_memory_rw(cpu, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0);
    guest_wstrncpy(cpu, the_filename, MAX_FILENAME, unicode_string.Buffer);
    //if(!strncmp(the_filename, "\\??\\", 4)) the_filename+=4;

    if(return_value) {
        fprintf(stderr, "Returning from NtCreateFile (error), return_value=%x, filename=%s, CreateOptions=%x\n", return_value, the_filename, CreateOptions);
    } else {
        fprintf(stderr, "%x: Returning from NtCreateFile (success), handle=%x, filename=%s, CreateOptions=%x\n",
            current_asid, handle, the_filename, CreateOptions);
    }
}


/*
  called whenever asid changes
*/
int asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    // XXX I wonder why this is in here?
    if (new_asid < 10) return 0;

    current_asid = new_asid;
    return 0;
}

#endif


bool init_plugin(void *self) {
#if defined(TARGET_I386) && !defined(TARGET_X86_64)
    PPP_REG_CB("syscalls2", on_NtReadFile_return, my_NtReadFile_return);
    PPP_REG_CB("syscalls2", on_NtOpenFile_return, my_NtOpenFile_return);
    PPP_REG_CB("syscalls2", on_NtCreateFile_return, my_NtCreateFile_return);

    panda_cb pcb;
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    return true;
#else
    std::cerr << PANDA_MSG "FileReadMon not supported on this arch." << std::endl;
    return false;
#endif
}

void uninit_plugin(void *self) {

}

}

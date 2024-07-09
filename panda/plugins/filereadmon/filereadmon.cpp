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

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

#include "osi_linux/osi_linux_ext.h"

#define MAX_FILENAME 256

extern "C" {

target_ulong current_asid = 0;

typedef struct _UNICODE_STRING {
    uint16_t Length;
    uint16_t MaximumLength;
    target_ulong Buffer;

} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	uint32_t Length;
	target_ulong RootDirectory;
	target_ulong ObjectName;
    // There's more stuff here but we're ignoring it.
} OBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        uint32_t Status;
        target_ptr_t Pointer;
    };
    target_ulong Information;
} IO_STATUS_BLOCK;

int panda_rw(CPUState *cpu, target_ulong addr, uint8_t *buf, int len, bool is_write) {
	int ret = panda_virtual_memory_rw(cpu, addr, buf, len, is_write);
	if (ret < 0) {
		fprintf(stderr, TARGET_FMT_lx ": panda_virtual_memory_rw (error), addr=" TARGET_FMT_lx ", len=%x, is_write=%x", current_asid, addr, len, is_write);
	}

	return ret;
}

uint32_t guest_wstrncpy(CPUState *cpu, char *buf, size_t maxlen, target_ulong guest_addr) {
    buf[0] = 0;
    unsigned i;
    for (i=0; i<maxlen; i++) {
        panda_rw(cpu, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
        if (buf[i] == 0) {
            break;
        }
    }
    buf[maxlen-1] = 0;
    return i;
}

#if defined(TARGET_I386)

void windows_read_return(CPUState *cpu, target_ulong FileHandle, uint32_t Event, target_ulong ApcRoutine, target_ulong ApcContext, target_ulong IoStatusBlock, target_ulong Buffer, uint32_t BufferLength, target_ulong ByteOffset, target_ulong Key) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	target_ulong return_value = env->regs[R_EAX];
	if(return_value) {
	} else {
		fprintf(stderr, TARGET_FMT_lx ": NtReadFile(FileHandle=" TARGET_FMT_lx ", Event=%x, ApcRoutine=" TARGET_FMT_lx ", ApcContext=" TARGET_FMT_lx ", IoStatusBlock=" TARGET_FMT_lx ", Buffer=" TARGET_FMT_lx ","
				"BufferLength=%x, ByteOffset=" TARGET_FMT_lx ", Key=" TARGET_FMT_lx ")\n", current_asid, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);

		IO_STATUS_BLOCK io_status_block;
		if (panda_rw(cpu, IoStatusBlock, (uint8_t *)&io_status_block, sizeof(io_status_block), 0) != -1) {
			fprintf(stderr, "Bytes Read=" TARGET_FMT_lx "\n", io_status_block.Information);

			// Print bytes read
			unsigned char *s=(unsigned char *)g_malloc(io_status_block.Information);
			if(s) {
				panda_rw(cpu, Buffer, (uint8_t *)s, io_status_block.Information, 0);
				for(int i=0; i<io_status_block.Information; i++) {
					fprintf(stderr, "%02x ", s[i]);
				}
				fprintf(stderr, "\n");
				free(s);
			}
		}
	}
}

void windows_open_return(CPUState *cpu, target_ulong FileHandle, target_ulong ObjectAttributes, uint32_t OpenOptions) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	target_ulong return_value = env->regs[R_EAX];

	// Get the file handle from the FileHandle pointer parameter
	char handle_buffer[30];
	target_ulong handle;
	if (panda_rw(cpu, FileHandle, (uint8_t *)&handle, sizeof(handle), 0) != -1) {
		sprintf(handle_buffer, TARGET_FMT_lx, handle);
	} else {
		sprintf(handle_buffer, "Failed to retrieve from guest");
	}

	char the_filename_buffer[MAX_FILENAME];
	char *the_filename = the_filename_buffer;
	OBJECT_ATTRIBUTES obj_attrs;
	UNICODE_STRING unicode_string;
	if (panda_rw(cpu, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0) != -1 &&
			panda_rw(cpu, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0) != -1) {
		guest_wstrncpy(cpu, the_filename, MAX_FILENAME, unicode_string.Buffer);
	} else {
		sprintf(the_filename_buffer, "Failed to retrieve from guest");
	}

	if(return_value) {
		fprintf(stderr, "Returning from NtOpenFile (error), return_value=" TARGET_FMT_lx ", filename=%s, OpenOptions=%x\n", return_value, the_filename, OpenOptions);
	} else {
		fprintf(stderr, TARGET_FMT_lx ": Returning from NtOpenFile (success), handle=%s, filename=%s, OpenOptions=%x\n", current_asid, handle_buffer, the_filename, OpenOptions);
	}
}

void windows_create_return(CPUState *cpu, target_ulong FileHandle, target_ulong ObjectAttributes, uint32_t CreateOptions) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	target_ulong return_value = env->regs[R_EAX];

	// Get the file handle from the FileHandle pointer parameter
	char handle_buffer[30];
	target_ulong handle;
	if (panda_rw(cpu, FileHandle, (uint8_t *)&handle, sizeof(handle), 0) != -1) {
		sprintf(handle_buffer, TARGET_FMT_lx, handle);
	} else {
		sprintf(handle_buffer, "Failed to retrieve from guest");
	}

	char the_filename_buffer[MAX_FILENAME];
	char *the_filename = the_filename_buffer;
	OBJECT_ATTRIBUTES obj_attrs;
	UNICODE_STRING unicode_string;
	if (panda_rw(cpu, ObjectAttributes, (uint8_t *)&obj_attrs, sizeof(obj_attrs), 0) != -1 &&
			panda_rw(cpu, obj_attrs.ObjectName, (uint8_t *)&unicode_string, sizeof(unicode_string), 0) != -1) {
		guest_wstrncpy(cpu, the_filename, MAX_FILENAME, unicode_string.Buffer);
	} else {
		sprintf(the_filename_buffer, "Failed to retrieve from guest");
	}

	if(return_value) {
		fprintf(stderr, "Returning from NtCreateFile (error), return_value=" TARGET_FMT_lx ", filename=%s, CreateOptions=%x\n", return_value, the_filename, CreateOptions);
	} else {
		fprintf(stderr, TARGET_FMT_lx ": Returning from NtCreateFile (success), handle=%s, filename=%s, CreateOptions=%x\n", current_asid, handle_buffer, the_filename, CreateOptions);
	}
}

void linux_read_return(CPUState *cpu, uint32_t fd, target_ulong buf, uint32_t count) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	ssize_t return_value = env->regs[R_EAX];

	if (0 == (return_value & 0x8000000)) {
		fprintf(stderr, TARGET_FMT_lx ": sys_read(fd=%x, buf=" TARGET_FMT_lx ", count=%x)\n", current_asid, fd, buf, count);
		fprintf(stderr, "Bytes Read=%x\n", count);

		// Print bytes read
		unsigned char *s=(unsigned char *)g_malloc(count);
		if(s) {
			panda_rw(cpu, buf, (uint8_t *)s, count, 0);
			for(int i = 0; i < count; i++) {
				fprintf(stderr, "%02x ", s[i]);
			}
			fprintf(stderr, "\n");
			free(s);
		}
	}
}

void linux_open_return(CPUState *cpu, target_ulong filename, int32_t flags, uint32_t mode) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	ssize_t return_value = env->regs[R_EAX];

	char the_filename_buffer[MAX_FILENAME];
	char *the_filename = the_filename_buffer;

	if (panda_rw(cpu, filename, (uint8_t *)the_filename, MAX_FILENAME, 0) == -1) {
		sprintf(the_filename_buffer, "Failed to retrieve from guest");
	}

	if (0 == (return_value & 0x8000000)) {
		fprintf(stderr, TARGET_FMT_lx ": Returning from sys_open (success), filename=%s, flags=%x, mode=%x\n", current_asid, the_filename, flags, mode);
	} else {
		fprintf(stderr, "Returning from sys_open (error), return_value=%lx, filename=%s, mode=%x\n", return_value, the_filename, mode);
	}
}

void linux_creat_return(CPUState *cpu, target_ulong pathname, uint32_t mode) {

	// Get the return value from EAX
	CPUArchState *env = (CPUArchState *)cpu->env_ptr;
	ssize_t return_value = env->regs[R_EAX];

	char the_filename_buffer[MAX_FILENAME];
	char *the_filename = the_filename_buffer;

	if (panda_rw(cpu, pathname, (uint8_t *)the_filename, MAX_FILENAME, 0) == -1) {
		sprintf(the_filename_buffer, "Failed to retrieve from guest");
	}

	if (0 == (return_value & 0x8000000)) {
		fprintf(stderr, TARGET_FMT_lx ": Returning from sys_creat (success),filename=%s, mode=%x\n", current_asid, the_filename, mode);
	} else {
		fprintf(stderr, "Returning from sys_creat (error), return_value=%lx, filename=%s, mode=%x\n", return_value, the_filename, mode);
	}
}

#if !defined(TARGET_X86_64)

void linux_read_return_32(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {

	linux_read_return(cpu, fd, buf, count);
}

void linux_open_return_32(CPUState* cpu, target_ulong pc, uint32_t filename, int32_t flags, uint32_t mode) {

	linux_open_return(cpu, filename,flags, mode);
}

void linux_creat_return_32(CPUState *cpu, target_ulong pc, uint32_t pathname, uint32_t mode) {

	linux_creat_return(cpu, pathname, mode);
}

void linux_pread_return_32(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint64_t pos) {

	linux_read_return(cpu, fd, buf, count);
}

// Print system call arguments and data read on successful return from NtReadFile system call

void windows32_read_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t ApcRoutine, uint32_t ApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {

    windows_read_return(cpu, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);
}

// Print return value, filename, and openoptions when NtOpenFile system call returns

void windows32_open_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {

    windows_open_return(cpu, FileHandle, ObjectAttributes, OpenOptions);
}

// Print return value, filename, and createoptions when NtCreateFile system call returns

void windows32_create_return(CPUState *cpu, target_ulong pc, uint32_t FileHandle, uint32_t DesiredAccess, uint32_t ObjectAttributes, uint32_t IoStatusBlock, uint32_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint32_t EaBuffer, uint32_t EaLength) {

    windows_create_return(cpu, FileHandle, ObjectAttributes, CreateOptions);
}

#elif defined(TARGET_X86_64)

void linux_read_return_64(CPUState *cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count) {

	linux_read_return(cpu, fd, buf, count);
}

void linux_open_return_64(CPUState* cpu, target_ulong pc, uint64_t filename, int32_t flags, uint32_t mode) {

	linux_open_return(cpu, filename,flags, mode);
}

void linux_creat_return_64(CPUState *cpu, target_ulong pc, uint64_t pathname, uint32_t mode) {

	linux_creat_return(cpu, pathname, mode);
}

void linux_pread_return_64(CPUState *cpu, target_ulong pc, uint32_t fd, uint64_t buf, uint32_t count, uint64_t pos) {

	linux_read_return(cpu, fd, buf, count);
}

// Print system call arguments and data read on successful return from NtReadFile system call

void windows64_read_return(CPUState *cpu, target_ulong pc, uint64_t FileHandle, uint64_t Event, uint64_t ApcRoutine, uint64_t ApcContext, uint64_t IoStatusBlock, uint64_t Buffer, uint32_t BufferLength, uint64_t ByteOffset, uint64_t Key) {

    windows_read_return(cpu, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);
}

// Print return value, filename, and openoptions when NtOpenFile system call returns

void windows64_open_return(CPUState *cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions) {

    windows_open_return(cpu, FileHandle, ObjectAttributes, OpenOptions);
}

// Print return value, filename, and createoptions when NtCreateFile system call returns

void windows64_create_return(CPUState *cpu, target_ulong pc, uint64_t FileHandle, uint32_t DesiredAccess, uint64_t ObjectAttributes, uint64_t IoStatusBlock, uint64_t AllocationSize, uint32_t FileAttributes, uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions, uint64_t EaBuffer, uint32_t EaLength) {

    windows_create_return(cpu, FileHandle, ObjectAttributes, CreateOptions);
}

#endif

/*
  called whenever asid changes
*/
bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid) {
    // XXX I wonder why this is in here?
    if (new_asid < 10) return false;

    current_asid = new_asid;
    return false;
}

#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386)
	panda_require("syscalls2");
	assert(init_syscalls2_api());

	// OS specific setup
	switch (panda_os_familyno) {
		case OS_WINDOWS: {

	#if !defined(TARGET_X86_64)
			PPP_REG_CB("syscalls2", on_NtReadFile_return, windows32_read_return);
			PPP_REG_CB("syscalls2", on_NtOpenFile_return, windows32_open_return);
			PPP_REG_CB("syscalls2", on_NtCreateFile_return, windows32_create_return);
	#elif defined(TARGET_X86_64)
			if ((0 == strcmp(panda_os_variant, "7sp0") ||
					(0 == strcmp(panda_os_variant, "7sp1")))) {
				PPP_REG_CB("syscalls2", on_NtReadFile_return, windows64_read_return);
				PPP_REG_CB("syscalls2", on_NtOpenFile_return, windows64_open_return);
				PPP_REG_CB("syscalls2", on_NtCreateFile_return, windows64_create_return);
			} else {
				fprintf(stderr,
						"ERROR: Windows is only supported on x86 (32-bit) and 64-bit Windows 7\n");
				return false;
			}
	#endif
		} break;
		case OS_LINUX: {
			panda_require("osi");
			assert(init_osi_api());
			panda_require("osi_linux");
			assert(init_osi_linux_api());
	#if !defined(TARGET_X86_64)

			PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return_32);
			PPP_REG_CB("syscalls2", on_sys_open_return, linux_open_return_32);
			PPP_REG_CB("syscalls2", on_sys_creat_return, linux_creat_return_32);
			PPP_REG_CB("syscalls2", on_sys_pread64_return, linux_pread_return_32);

	#elif defined(TARGET_X86_64)

			PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return_64);
			PPP_REG_CB("syscalls2", on_sys_open_return, linux_open_return_64);
			PPP_REG_CB("syscalls2", on_sys_creat_return, linux_creat_return_64);
			PPP_REG_CB("syscalls2", on_sys_pread64_return, linux_pread_return_64);
	#endif
		} break;
		default: {
			fprintf(stderr, "filereadmon: OS not supported!\n");
			return false;
		}
	}

	panda_cb pcb;
	pcb.asid_changed = asid_changed;
	panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

	return true;

#else
    fprintf(stderr, "filereadmon: Only i386 is supported!\n");
    return false;
#endif
}

void uninit_plugin(void *self) {

}

}

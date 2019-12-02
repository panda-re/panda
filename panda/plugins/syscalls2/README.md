Plugin: syscalls2
===========

Summary
-------

The `syscalls2` plugin provides callbacks that allow notification whenever system calls occur in the guest, and can provide the parameters for each system call as long as the guest operating system (OS) is one of those supported by `syscalls2`.

This is accomplished by automatically generating a bunch of code based on an initial prototypes file. For full details, have a look at `syscalls2/scripts/syscall_parser.py` and one of the prototypes files, such as `syscalls2/generated-in/linux_x86_prototypes.txt`.

For adding support for a new OS or updating the existing ones, see `MAINTENANCE.md`.

The profile for the appropriate guest OS is selected automatically from the information specified in the "-os" argument to PANDA.

Arguments
---------

* `load-info`: boolean, defaults to `false`. Enables loading of system call information for the selected OS profile. This allows more generic processing of system call events, without having to implement individual hooks.

Dependencies
------------

None.

APIs and Callbacks
------------------

### Callbacks
The `syscalls2` plugin defines one callback for each system call in each operating system (far too many to list here). To see the prototypes for each one, you can look at the file `generated/syscalls_ext_typedefs.h`.

Each callback is named `on_${SYSCALLNAME}_enter` for calls and `on_${SYSCALLNAME}_return` for returns. The parameters are the CPU state pointer, program counter, and then the arguments to the system call.

In addition to the OS-specific system calls, there are four callbacks defined that apply to all OSes:

Name: **on_unknown_sys_enter**

Signature:

```C
typedef void (*on_unknown_sys_enter_t)(CPUState *env, target_ulong pc, target_ulong callno)
```

Description: Called when an unknown system call (i.e., one that does not have a callback already defined for it) is invoked in the guest. The system call number will be available in the `callno` parameter.

Name: **on_unknown_sys_return**

Signature:

```C
typedef void (*on_unknown_sys_return_t)(CPUState *env, target_ulong pc, target_ulong callno)
```

Description: Called when an unknown system call (i.e., one that does not have a callback already defined for it) returns in the guest. The system call number will be available in the `callno` parameter.

Name: **on_all_sys_enter**

Signature:

```C
typedef void (*on_all_sys_enter_t)(CPUState *env, target_ulong pc, target_ulong callno)
```

Description: Called for every system call invoked in the guest. The call number is available in the `callno` parameter. This callback does minimal processing on the side of `syscalls2` plugin.

Name: **on_all_sys_return**

Signature:

```C
typedef void (*on_all_sys_return_t)(CPUState *env, target_ulong pc, target_ulong callno)
```

Description: Called whenever any system call returns in the guest. The call number is available in the `callno` parameter. This callback does minimal processing on the side of `syscalls2` plugin.

Name: **on_all_sys_enter2**

Signature:

```C
typedef void (*on_all_sys_enter2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp)
```

Description: Called for every system call invoked in the guest. The `call` parameter is used to provide information about the system call. The `rp` parameter is used to provide information about the context of the system call (asid, argument values etc). This means that some additional processing is required on the side of the `syscalls2` plugin. You need to have the `load-info` flag enabled for `syscalls2` to use this variant of the callback.

Name: **on_all_sys_return2**

Signature:

```C
typedef void (*on_all_sys_return2_t)(CPUState *cpu, target_ulong pc, const syscall_info_t *call, const syscall_ctx_t *rp)
```

Description: Called whenever any system call returns in the guest. The `call` parameter is used to provide information about the system call. The `rp` parameter is used to provide information about the context of the system call (asid, argument values etc). This means that some additional processing is required on the side of the `syscalls2` plugin. You need to have the `load-info` flag enabled for `syscalls2` to use this variant of the callback.


### API calls
Finally the plugin provides two API calls:

Name: **get_syscall_retval**

Signature:

```C
target_long get_syscall_retval(CPUState *cpu)
```

Description: Retrieves the return value of a system call, abstracting away architecture-specific details. The call must be made in the appropriate context, so that the return value is still available (e.g. in a `on_all_sys_return` callback).

Name: **get_syscall_info**

Signature:

```C
const syscall_info_t *get_syscall_info(uint32_t callno)
```

Description: Returns a pointer to a `syscall_info_t` struct containing information about the specified system call. Available only when the `load-info` flag of the plugin has been turned on.

Name: **get_syscall_meta**

Signature:

```C
const syscall_meta_t *get_syscall_meta(void)
```

Description: Returns a pointer to a `syscall_meta_t` struct containing meta-information about the system calls of the guest operating system. Available only when the `load-info` flag of the plugin has been turned on.



Example
-------

In general one uses `syscalls2` with another plugin that registers callbacks for specific set of system calls. For example, one could write a plugin called `filereadmon` that intercepts calls to `NtReadFile` on Windows using something like:

```C
#include "plugin/plugin.h"
#include "panda/plugin_plugin.h"
#include "syscalls2/syscalls_ext_typedefs.h"

void my_NtReadFile_enter(
        CPUState* env,
        target_ulong pc,
        uint32_t FileHandle,
        uint32_t Event,
        uint32_t UserApcRoutine,
        uint32_t UserApcContext,
        uint32_t IoStatusBlock,
        uint32_t Buffer,
        uint32_t BufferLength,
        uint32_t ByteOffset,
        uint32_t Key) {
   printf("NtReadFile(FileHandle=%x, Event=%x, UserApcRoutine=%x, "
                     "UserApcContext=%x, IoStatusBlock=%x, Buffer=%x, "
                     "BufferLength=%x, ByteOffset=%x, Key=%x)\n",
        FileHandle, Event, UserApcRoutine, UserApcContext,
        IoStatusBlock, Buffer, BufferLength, ByteOffset, Key);
}

// ...

bool init_plugin(void *self) {
    PPP_REG_CB("syscalls2", on_NtReadFile_enter, my_NtReadFile_enter);
    return true;
}

// ...

```

And then invoke it as:

```sh
$PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
    -os windows-32-7 -panda syscalls2 -panda filereadmon
```

If you'd like more examples, you can have a look at `loaded`, `filereadmon` and `file_taint`, all of which use `syscalls2`.

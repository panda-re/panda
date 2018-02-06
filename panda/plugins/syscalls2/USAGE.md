Plugin: syscalls2
===========

Summary
-------

The `syscalls2` plugin provides callbacks that allow notification whenever system calls occur in the guest, and can provide the parameters for each system call as long as the guest OS is one of these supported by `syscalls2`.

This is accomplished by automatically generating a bunch of code based on an initial prototypes file. For full details, have a look at `syscalls2/syscall_parser.py` and one of the prototypes files, such as `syscalls2/prototypes/linux_x86_prototypes.txt`.

FIXME: We should include a list of steps for adding support for a new OS to `syscalls2` here. It's a little tricky.

Arguments
---------

* `profile`: string, defaults to "linux\_x86". The guest OS profile to use. This determines how system calls (e.g. the `sysenter` instruction) will actually be interpreted. Available options are: `linux_x86`, `linux_arm`, `windows_xpsp2_x86`, `windows_xpsp3_x86`, and `windows_7_x86`.
* `load-info`: boolean, defaults to `false`. Enables loading of system call information for the selected OS profile. This allows more generic processing of system call events, without having to implement individual hooks.

Dependencies
------------

None.

APIs and Callbacks
------------------

### Callbacks
The `syscalls2` plugin defines one callback for each system call in each operating system (far too many to list here). To see the prototypes for each one, you can look at the file `gen_syscalls_ext_typedefs.h`.

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

Description: Called for every system call invoked in the guest. The call number is available in the `callno` parameter.

Name: **on_all_sys_return**

Signature:

```C
typedef void (*on_all_sys_return_t)(CPUState *env, target_ulong pc, target_ulong callno)
```

Description: Called whenever any system call returns in the guest. The call number is available in the `callno` parameter.

### API calls
Finally the plugin provides one API call:

Name: **get_syscall_info**

Signature:

```C
syscall_info_t *get_syscall_info(uint32_t callno)
```

Description: Returns a pointer to a `syscall_info_t` struct containing information about the specified system call. Available only when the `load-info` flag of the plugin has been turned on.


Example
-------

In general one uses `syscalls2` with another plugin that registers callbacks for specific set of system calls. For example, one could write a plugin called `filereadmon` that intercepts calls to `NtReadFile` on Windows using something like:

```C
#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../syscalls2/syscalls_common.h"
#include "panda/plugin_plugin.h"

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
$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
    -os windows-32-7 -panda syscalls2:profile=windows_7_x86 -panda filereadmon
```

If you'd like more examples, you can have a look at `win7proc` and `file_taint`, which both use `syscalls2` extensively.

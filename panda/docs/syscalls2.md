System calls 2 plugin 
====

The `syscalls2` plugin provides callbacks for system call entry and exit for a few operating systems and architectures.
This kind of "operating system introspection" can be invaluable when reverse engineering.
Without it, PANDA provides little more than a replay of an opaque intruction stream. 

`syscalls2` is made possible through the magic of auto-generated code. 
Given a file which contains a list of system calls along with numbers and prototypes,
a Python script digests that to generate code that is compiled to perform all the necessary instrumentation.

If you look in the `syscalls2` plugin directory, you will see a number of files used to drive autogeneration of code:

    linux_arm_prototypes.txt
    linux_x86_prototypes.txt
    windows7_x86_prototypes.txt
    ...

Each line in each of these files is the prototype for a system call, with named paramters.
The number at the beginning of each line is the system call number.
On x86, for instance, you load that number into the EAX register, push arguments to the stack,
and then execute the `systenter` instruction to invoke a system call.

For Windows prototypes, whose signatures do not change between OS releases (though functions may be added or removed, changing the numbering), there is an additional layer of autogeneration -- a master `all_windows_prototypes.txt` which contains the prototypes themselves, and is used by the `createWindowsPrototypes.py` script to renumber the calls for each OS. Volatility's system call tables are used to perform the renumbering.


Caveats
----

Linux x86 and ARM, as well as several versions of Windows x86 are currently supported. 64-bit versions of Windows are not currently supported, because we have not yet implemented the 64-bit Windows system call ABI. Patches for 64-bit support would be greatly appreciated!


Use
----

If all you want to do is use this plugin, just read this bit. 

Let's say you want to write a plugin that does something when certain Win7 system calls are encountered along a trace
on replay (note that plugins only operate on replay).
For instance, you might want to know when a process is created and when one is destroyed, performing some interrogation
of the associated Windows data structures at those points in time to ascertain things like pid and process names.

The relevant system calls for Windows 7 are `NtCreateUserProcess` and `NtTerminateProcess`, and their prototypes
can be found in `windows7_x86_prototypes.txt`.

     NTSTATUS NtCreateUserProcess 
       (PHANDLE ProcessHandle, 
        PHANDLE ThreadHandle, 
        ACCESS_MASK ProcessDesiredAccess, 
        ACCESS_MASK ThreadDesiredAccess, 
        POBJECT_ATTRIBUTES ProcessObjectAttributes, 
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags, 
        ULONG ThreadFlags,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters, 
        PPROCESS_CREATE_INFO CreateInfo, 
        PPROCESS_ATTRIBUTE_LIST AttributeList)

     NTSTATUS NtTerminateProcess
       (HANDLE ProcessHandle, 
        NTSTATUS ExitStatus)

At this point you might ask "How did you know to focus on those system calls?"
A good question, and one to which we have no good answer, unfortunately.
The `syscalls2` plugin provides a reasonable interface to the various Windows and Linux system calls.
But you need to bring to it a working knowledge of that system interface.
That probably means reading "Windows Internals" by Russinovich.
For Linux, you can read a book (there are several Linux Kernel books) or look at man pages and / or source code.

The `syscalls2` plugin provides callbacks for entry and exit to both of these process-related system calls.
By 'entry', we mean right before the `sysenter` executes.
By 'exit' we mean when PANDA is about to execute the instruction immediately after that `sysenter` 
(determined by a call stack maintained by the `syscalls2` plugin).

The callback functions you write will have, as their first two arguments, a pointer to the 
cpu state `env` and the program counter.
The rest of the arguments are all unsigned integers representing the actual system call arguments.
For instance, the callback for enter to `NtTerminateProcess` has the following type.

    typedef void (*on_NtTerminateProcess_enter_t)
      (CPUState* env,
       target_ulong pc,
       uint32_t ProcessHandle,
       uint32_t ExitStatus);

If you compare this type signature with that for NtTerminateProcess, above, you will easily observer the correspondence.
You register a callback with `syscalls2` using the [PPP](https://github.com/moyix/panda/blob/master/docs/ppp.md) mechanism.
That is, if you had written a function `my_NtTerminateProcess_enter` in your plugin to have the type
`on_NtTerminateProcess_enter_t`, then you would add the following to the `init_plugin` function of the plugin in 
order to register it. 

    PPP_REG_CB("syscalls2", on_NtTerminateProcess_enter, my_NtTerminateProcess_enter);

At this point you may want to study the sort of code in the `win7proc` plugin, which uses `syscalls2` on Windows 7,
and also includes some gnarly code for retrieving objects and traversing Windows handle tables. 
Or you might like to stare at the code in the `file_taint` plugin which uses `syscalls2` with Linux and Windows to track
file open and read operations and uses that to add taint labels to the bytes read out of a file.
These are two good examples of what one might do with `syscalls2`.

Note that `syscalls2` is structured so that if a system call shares the same semantics across multiple operating systems, you can intercept it with a single callback. For example, once you have written the `on_NtTerminateProcess_enter` callback above, no extra work is needed to make it work on Windows XP SP3 -- you just need to run the plugin with `-panda syscalls2:profile=windowsxp_sp3_x86` instead of `windows7_x86`.

The OS Profile
----

Once you have written a plugin that makes use of `syscalls2`, you will have to enable it on the panda commandline
in such a way that `syscalls2` knows what operating system to assume when trying to instrument system calls
with callbacks.
If your plugin is called `my_plugin`, then to run that plugin on a Win7 32-bit replay, the commandline should contain

    -panda 'syscalls2:profile=windows7_x86'

There are currently five supported OS profiles.

    windows7_x86
    windowsxp_sp2_x86
    windowsxp_sp3_x86
    linux_x86
    linux_arm


Autogenerating system call introspection
----

If you are interested in the details of how we autogenerate system call introspection code, here is a sketch. 

Notice that all of the necessary information for building introspection code for a system call is contained in the call prototype, aside from a little domain knowledge about how system calls work on an architecture & operating system.
The script `recreate_all_os_arch.sh` in the `syscalls2` directory can be run to re-generate code.
That script, in turn, simply runs the script `syscall_parser.py` with arguments that tell it to generate code for the operating systems and architectures given on the command line.

The script produces the following files:

    gen_syscalls_ext_typedefs.h

This file contains two lines per system call prototype and defines the types of the `_enter` and `_return` callbacks.

    gen_syscall_ppp_boilerplate_enter.cpp
    gen_syscall_ppp_boilerplate_return.cpp
    gen_syscall_ppp_register_enter.cpp
    gen_syscall_ppp_register_return.cpp
    gen_syscall_ppp_extern_enter.h
    gen_syscall_ppp_extern_return.h

These six files are all the necessary code to make PPP work for system calls.

Finally, for each OS, we will have two files that contain the code responsible for handling each individual system call. They contain a large C switch statment with a case for each system call number. For each, the arguments to the call are made available and then run on all registered callbacks.

    gen_syscall_switch_enter_linux_x86.cpp
    gen_syscall_switch_return_linux_x86.cpp

Adding Support for a New Operating System
----

Adding support for a new operating system is relatively simple, provided you have a prototypes file in the correct format. For example, suppose you want to add `newos`, which is an operating system for x86. The prototypes file would be named `newos_x86_prototypes.txt`. Then:

1. Add `newos` to the `KNOWN_OS` variable in syscall_parser.py
2. Edit `recreate_all_os_arch.sh` and add `newos x86` to the end of the command line.
3. Add another enum for it in `syscalls2.cpp` and fill out the per-profile function pointers for it; these functions essentially tell `syscalls2` what the system call ABI is (i.e., how to retrieve the system call arguments).
4. Add another case to the if statement in `init_plugin`, so that it recognizes `newos_x86` as a valid profile.
5. Add the `gen_syscall_switch_enter_newos_x86.cpp` and `gen_syscall_switch_return_newos_x86.cpp` files to the Makefile.
6. Add the prototypes for `syscall_enter_switch_newos_x86` and `syscall_return_switch_newos_x86` functions to `syscalls2.h`.
7. Re-run `./recreate_all_os_arch.sh` to generate the code for the switch statements.

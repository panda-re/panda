System calls 2 plugin 
====

The `syscalls2` plugin provides callbacks for system call entry and exit for a few operating systems and architectures.
This kind of "operating system introspection" can be invaluable when reverse engineering.
Without it, PANDA provides little more than a replay of an opaque intruction stream. 

`syscalls2` is made possible through the magic of auto-generated code. 
Given a file which contains a list of system calls along with numbers and prototypes,
a Python script digests that to generate code that is compiled to perform all the necessary instrumentation.

If you look in the `syscalls2` plugin directory, you will see three files used to drive autogeneration of code:

    linux_arm_prototypes.txt
    linux_x86_prototypes.txt
    windows7_x86_prototypes.txt

Each line in each of these files is the prototype for a system call, with named paramters.
The number at the beginning of each line is the system call number.
On x86, for instance, you load that number into the EAX register, push arguments to the stack,
and then execute the `systenter` instruction to invoke a system call.  


Caveats
----
Only Linux and Windows 7 are currently supported. 
Only 32-bit x86. 
Yes, that means 64-bit Win7 won't work. So don't try. Or, better yet, fix it for us!


Use
----

If all you want to do is use this plugin, just read this bit. 

Let's say you want to write a plugin that does something when certain Win7 system calls are encountered along a trace
on replay (note that plugins only operate on replay).
For instance, you might want to know when a process is created and when one is destroyed, performing some interrogation
of the associated windows data structures at those points in time to ascertain things like pid and process names.

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
The `syscalls2` plugin provides a reasonable interface to the various windows and linux system calls.
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

At this point you may want to study the sort of code in the `win7proc` plugin, which uses `syscalls2` on windows 7,
and also includes some gnarly code for retrieving objects and traversing Windows handle tables. 
Or you might like to stare at the code in the `file_taint` plugin which uses `syscalls2` with Linux to track
file open and read operations and uses that to add taint labels to the bytes read out of a file.  
These are two good examples of what one might do with `syscalls2`.

The OS Profile
----

Once you have written a plugin that makes use of `syscalls2`, you will have to enable it on the panda commandline
in such a way that `syscalls2` knows what operating system to assume when trying to instrument system calls
with callbacks.
If your plugin is called `my_plugin`, then to run that plugin on a win7 32-bit replay, the commandline should contain

    -panda 'syscalls2:profile=windows7_x86;

There are currently only three supported OS profiles.

    windows7_x86
    linux_x86
    linux_arm


Autogenerating system call introspection
----

If you are interested in the details of how we autogenerate system call introspection code, here is a sketch. 

Notice that all of the necessary information for building introspection code for a system call is contained in the call prototype, aside from a little domain knowledge about how system calls work on an architecture & operating system.
The script `recreate_all_os_arch.sh` in the `syscalls2` directory can be run to re-generate code.
That script, in turn, simply runs the script `syscall_parser.py` three times, once for each profile.

Consider the output of that script for just "linux_x86".

    gen_syscalls_ext_typedefs_linux_x86.h

This file contains two lines per system call prototype and defines the types of the `_enter` and `_return` callbacks.

    gen_syscall_switch_enter_linux_x86.cpp
    gen_syscall_switch_return_linux_x86.cpp

These two files contain a large C switch statment with a case for each system call number.
For each, the arguments to the call are made available and then run on all registered callbacks.

    gen_syscall_ppp_boilerplate_linux_x86.cpp         
    gen_syscall_ppp_boilerplate_enter_linux_x86.cpp   
    gen_syscall_ppp_boilerplate_return_linux_x86.cpp  
    gen_syscall_ppp_register_enter_linux_x86.cpp      
    gen_syscall_ppp_register_return_linux_x86.cpp     

These five files are all the necessary code to make PPP work for system calls.


# panda-gdb

## Summary

A mixed-level approach for debugging which attempts to fit a userland-style of debugging into a hypervisor debugger by using PANDA's OSI plugin in order to allow for having an understanding of processes, memory layouts, etc. while still allowing to step through the kernel from the hypervisor.

### Usage

Currently only designed to be used with replays.

Example usage:

```
panda-system-x86_64 -os "linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr" -replay catmaps -panda gdb:on_entry=1 -m 1G
```

Example of connecting to them:

```
$ gdb-multiarch

(gdb) target remote localhost:4444
```

Checking the registers:

```
(gdb) info reg
rax            0x1c                28
rbx            0x4                 4
rcx            0x7ffff7de59a0      140737351932320
rdx            0x0                 0
rsi            0x7fffffffeba0      140737488350112
rdi            0x0                 0
rbp            0x7ffff7ffe700      0x7ffff7ffe700
rsp            0x1                 0x1
r8             0x3028              12328
r9             0x1000000           16777216
r10            0x1                 1
r11            0x0                 0
r12            0x555555556710      93824992241424
r13            0x7fffffffeba0      140737488350112
r14            0x0                 0
r15            0x0                 0
rip            0x555555556710      0x555555556710
eflags         0x202               [ IF ]
cs             0x0                 0
ss             0x0                 0
ds             0x0                 0
es             0x0                 0
fs             0xf7fef540          -134286016
gs             0x0                 0
```

Here are some of the other commands that have been tested and which work:
* `c` (continue)
* `b` (set breakpoint)
* `si` (step)
* `x` (read memory)

### Monitor Commands

panda-gdb provides a set of monitor commands in order to allow accessing PANDA-specific
functionality such as dynamic taint analysis and process lists. The following commands 
are supported:

* `meminfo` - print out the current memory map
* `taint` - apply taint to a given register/memory location
* `check_taint` - check if a given register/memory location is tainted
* `get_taint` - get the taint labels for a given register/memory location
* `threadinfo` - get info about threads of the current process
* `procinfo` - get info about the current process
* `proclist` - list all the currently running processes

### Dependencies

* `osi`

### Arguments

* `on_entry`: bool, optional. Defaults to true. If set to true, process will break on the entrypoint of the first process.
* `file`: String, optional. If set, process will break when the process of filename `file` starts.


Plugin: filereadmon
===========

Summary
-------

This is a proof of concept plugin that illustrates how a plugin can make use of
the syscalls2 plugin to perform a targeted analysis of a binary.  This plugin
prints out the names of opened files.  It also dumps the stream of bytes read
from input files.

This plugin can be ran with Windows (only supports x86 (32-bit) and 64-bit Windows 7) and any supported Linux OS.

**Note:** Analysis can't be done for 32-bit apps running on a 64-bit guest at the momemnt since *syscall2* does not yet support it.

Arguments
---------

None

Dependencies
------------

`filereadmon` depends on **syscalls2** to intercept the appropriate file-related APIs (`open`, `read`, etc.).

If plugin is being used for a Linux OS then it also depends on the **osi** plugin to get information about file objects from their file descriptors. The **osi_linux** plugin is also needed to provide the Linux introspection information.

APIs and Callbacks
------------------

None.

Example
-------

```
    $PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo \
        -os windows-32-xpsp3 -panda filereadmon
```

```
    $PANDA_PATH/x86_64-softmmu/panda-system-x86_64 -replay foo \
    -panda osi \
    -panda osi_linux:kconf_group=ubuntu:5.3.0-28-generic:64 \
    -os linux-64-ubuntu -panda filereadmon
```

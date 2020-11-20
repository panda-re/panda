Plugin: filereadmon
===========

Summary
-------

This is a proof of concept plugin that illustrates how a plugin can make use of
the syscalls2 plugin to perform a targeted analysis of a binary.  This plugin
prints out the names of opened files.  It also dumps the stream of bytes read
from input files.

Arguments
---------

None

Dependencies
------------

`filereadmon` depends on **syscalls2** to intercept the appropriate file-related APIs (`open`, `read`, etc.).

APIs and Callbacks
------------------

None.

Example
-------

```
    $PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo \
        -os windows-32-xpsp3 -panda filereadmon
```

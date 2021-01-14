Plugin: loaded
===========

Summary
-------

This plugin prints when executable pages are mapped in memory.

Arguments
---------

None

Dependencies
------------

`filereadmon` depends on **syscalls2, osi, and osi\_linux** to intercept the appropriate system calls that relate to mapping executable pages in memory.

APIs and Callbacks
------------------

None.

Example
-------

```
    $PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo \
        -panda loaded -os linux-32-debian-3.2.81-686-pae
```

Plugin: pri_dwarf
===========

Summary
-------

The `pri_dwarf` plugin is a provider plugin for `pri` (see [pri](pri/USAGE.md)).  It examines dwarf information for an executable using `libdwarf.h`, `dwarf.h` and `elf.h`.  The plugin also hooks mmap syscalls using the `loaded` plugin (see [loaded](loaded/loaded.cpp)) in order to find shared objects loaded during the lifetime of a program's execution.  At these load points, `pri_dwarf` will load the dwarf information for the .so file if such information exists.

Arguments
---------

* `g_debugpath`: string, defaults to "dbg". The path to the debugging file on the guest.
* `h_debugpath`: string, defaults to "dbg". The path to the debugging file on the host.
* `proc`: string, defaults to "None". The name of the process to monitor using DWARF information.

Dependencies
------------

Requires `osi` and an `osi` provider plugin.  Furthermore it requires `loaded` (hopefully this will end up in `osi`).

APIs and Callbacks
------------------

Provides only support for `pri` callbacks.

Example
-------

Below is an example command line usage of `pri_dwarf`:

    ~/git/panda/qemu/i386-softmmu/qemu-system-i386 -replay \
        /nas/ulrich/dwarf_tshark_capture2/wireshark-1.2.1-saurabh.cap.iso \
        -panda osi \
        -panda osi_linux:kconf_file=/nas/ulrich/kernelinfo.conf,kconf_group=debian-3.2.51-i686 \
        -panda pri \
        -panda pri_dwarf:proc=tshark,g_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/,h_debugpath=/nas/ulrich/wireshark-1.2.1/lava-install/

An example implementaiton using the `pri_dwarf` plugin can be found at [pri_simple](pri_simple/pri_simple.cpp).
